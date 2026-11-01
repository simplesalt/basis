"""oidc-keys-sync: publish the cluster's public signing keys to Cloudflare KV.

OpenRouter workload identity federation fetches the cluster's key set from
https://oidc.simplesalt.company/openid/v1/jwks. That host is a Cloudflare
Worker (simplesalt/cloud-basis, 20-resources/cloudflare/oidc-keys) that
serves the KV key "jwks" and a fixed discovery document; nothing on it routes
into the cluster.

The key set only changes when the service-account signing key is rotated, and
a rotation only takes effect when an API server restarts. Every API server
process holds a Lease in kube-system (label
apiserver.kubernetes.io/identity=kube-apiserver) whose holderIdentity carries
a fresh UUID per process. So this program:

  1. publishes once at start-up;
  2. watches those Leases and publishes again only when one appears or its
     holderIdentity changes (an API server restarted). Renewals, which only
     move renewTime, are ignored.

Publishing reads /openid/v1/jwks with this pod's own token, reads the KV
namespace id from KvNamespace cf-main-kv-oidc-keys, and server-side applies Kv
oidc-jwks only if it does not already hold exactly that key set; Crossplane
writes the value to Cloudflare. No Cloudflare credential is used here.
"""

import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request

API = os.environ.get("API_SERVER", "https://kubernetes.default.svc")
SA_DIR = os.environ.get("SA_DIR", "/var/run/secrets/kubernetes.io/serviceaccount")
TARGET_NS = os.environ.get("TARGET_NAMESPACE", "crossplane-system")
KV_NAMESPACE = os.environ.get("KV_NAMESPACE_OBJECT", "cf-main-kv-oidc-keys")
KV_OBJECT = os.environ.get("KV_OBJECT", "oidc-jwks")
KEY_NAME = os.environ.get("KEY_NAME", "jwks")
ACCOUNT_ID = os.environ["CLOUDFLARE_ACCOUNT_ID"]
PROVIDER_CONFIG = os.environ.get("PROVIDER_CONFIG", "ssint-main")
WATCH_SECONDS = int(os.environ.get("WATCH_SECONDS", "3600"))
RETRY_SECONDS = int(os.environ.get("RETRY_SECONDS", "30"))
FIELD_MANAGER = "oidc-keys-sync"

GROUP = "workers.upjet-cloudflare.m.upbound.io/v1alpha1"
KVNS_PATH = "/apis/%s/namespaces/%s/kvnamespaces/%s" % (GROUP, TARGET_NS, KV_NAMESPACE)
KV_PATH = "/apis/%s/namespaces/%s/kvs/%s" % (GROUP, TARGET_NS, KV_OBJECT)
LEASES_PATH = "/apis/coordination.k8s.io/v1/namespaces/kube-system/leases"
LEASE_SELECTOR = "apiserver.kubernetes.io%2Fidentity%3Dkube-apiserver"


def log(level, msg, **kw):
    print(json.dumps({"level": level, "msg": msg, **kw}), flush=True)


def token():
    with open(os.path.join(SA_DIR, "token")) as f:
        return f.read().strip()


def context():
    return ssl.create_default_context(cafile=os.path.join(SA_DIR, "ca.crt"))


def request(path, method="GET", body=None, ctype=None, accept="application/json"):
    headers = {"Authorization": "Bearer " + token(), "Accept": accept}
    if ctype:
        headers["Content-Type"] = ctype
    req = urllib.request.Request(API + path, data=body, method=method, headers=headers)
    with urllib.request.urlopen(req, context=context(), timeout=10) as resp:
        return json.loads(resp.read())


def get_or_none(path):
    try:
        return request(path)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise


def desired(namespace_id, value):
    return {
        "apiVersion": GROUP,
        "kind": "Kv",
        "metadata": {
            "name": KV_OBJECT,
            "namespace": TARGET_NS,
            "labels": {
                "app.kubernetes.io/name": "oidc-keys-sync",
                "app.kubernetes.io/part-of": "identity",
                "app.kubernetes.io/managed-by": FIELD_MANAGER,
                "entity": "cluster",
                "capability": "identity",
            },
        },
        "spec": {
            "forProvider": {
                "accountId": ACCOUNT_ID,
                "namespaceId": namespace_id,
                "keyName": KEY_NAME,
                "value": value,
            },
            "providerConfigRef": {"kind": "ProviderConfig", "name": PROVIDER_CONFIG},
        },
    }


def publish(reason):
    """Publish the live key set if it differs. Returns True when settled."""
    jwks = request("/openid/v1/jwks", accept="application/jwk-set+json, application/json")
    if not jwks.get("keys"):
        log("error", "API server returned an empty key set; not publishing it", reason=reason)
        return False
    value = json.dumps(jwks, separators=(",", ":"))
    kids = [k.get("kid") for k in jwks["keys"]]

    kvns = get_or_none(KVNS_PATH)
    namespace_id = ((kvns or {}).get("status", {}).get("atProvider", {}) or {}).get("id")
    if not namespace_id:
        log("warn", "KV namespace not ready yet; nothing published", object=KV_NAMESPACE, reason=reason)
        return False

    current = get_or_none(KV_PATH)
    fp = ((current or {}).get("spec", {}).get("forProvider", {})) or {}
    if fp.get("value") == value and fp.get("namespaceId") == namespace_id and fp.get("keyName") == KEY_NAME:
        log("info", "published key set already current", kids=kids, reason=reason)
        return True

    request(
        KV_PATH + "?fieldManager=%s&force=true" % FIELD_MANAGER,
        method="PATCH",
        body=json.dumps(desired(namespace_id, value)).encode(),
        ctype="application/apply-patch+yaml",
    )
    log("info", "published key set updated", kids=kids, created=current is None, reason=reason)
    return True


def list_leases():
    doc = request(LEASES_PATH + "?labelSelector=" + LEASE_SELECTOR)
    holders = {i["metadata"]["name"]: i.get("spec", {}).get("holderIdentity") for i in doc.get("items", [])}
    return holders, doc["metadata"]["resourceVersion"]


def watch(resource_version):
    """Yield (event type, Lease object) until the watch ends."""
    path = "%s?labelSelector=%s&watch=true&allowWatchBookmarks=true&resourceVersion=%s&timeoutSeconds=%d" % (
        LEASES_PATH, LEASE_SELECTOR, resource_version, WATCH_SECONDS)
    req = urllib.request.Request(API + path, headers={"Authorization": "Bearer " + token()})
    with urllib.request.urlopen(req, context=context(), timeout=WATCH_SECONDS + 30) as resp:
        for line in resp:
            if not line.strip():
                continue
            ev = json.loads(line)
            obj = ev.get("object", {})
            if ev.get("type") == "ERROR":
                raise RuntimeError("watch error: %s" % obj.get("message"))
            yield ev["type"], obj


def run():
    pending = "start-up"
    holders, rv = None, None
    while True:
        try:
            if pending and publish(pending):
                pending = None
            if holders is None:
                holders, rv = list_leases()
            for etype, obj in watch(rv):
                meta = obj.get("metadata", {})
                rv = meta.get("resourceVersion", rv)
                if etype == "BOOKMARK":
                    continue
                name = meta.get("name")
                holder = obj.get("spec", {}).get("holderIdentity")
                if etype == "DELETED":
                    holders.pop(name, None)
                    continue
                if holders.get(name) != holder:
                    holders[name] = holder
                    log("info", "API server restarted", lease=name, holder=holder)
                    pending = "api server restart"
                if pending and publish(pending):
                    pending = None
        except urllib.error.HTTPError as e:
            if e.code == 410:
                holders = None
                pending = pending or "watch expired"
                continue
            log("error", "request failed", code=e.code, error=str(e))
            pending = pending or "retry"
            time.sleep(RETRY_SECONDS)
        except Exception as e:
            log("error", "sync loop error", error=str(e))
            holders = None
            pending = pending or "retry"
            time.sleep(RETRY_SECONDS)


if __name__ == "__main__":
    log("info", "oidc-keys-sync watching API server identity leases")
    try:
        run()
    except KeyboardInterrupt:
        sys.exit(0)
