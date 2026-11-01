"""oidc-keys-sync: copy the cluster's public signing keys to Cloudflare KV.

OpenRouter workload identity federation fetches the cluster's key set from
https://oidc.simplesalt.company/openid/v1/jwks. That host is a Cloudflare
Worker (simplesalt/cloud-basis, 20-resources/cloudflare/oidc-keys) that
serves the KV key "jwks" and a fixed discovery document; nothing on it routes
into the cluster. This job keeps that KV key equal to the API server's live
key set, so a key rotation needs no manual step:

  1. read /openid/v1/jwks with this pod's own token (the built-in
     system:service-account-issuer-discovery binding allows it);
  2. read the KV namespace id from KvNamespace cf-main-kv-oidc-keys;
  3. if Kv oidc-jwks does not already hold exactly that key set, server-side
     apply it; Crossplane writes the value to Cloudflare.

No Cloudflare credential is used here. Until the KvNamespace exists and has an
id, the job logs that it is waiting and exits 0.
"""

import json
import os
import ssl
import sys
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
FIELD_MANAGER = "oidc-keys-sync"

GROUP = "workers.upjet-cloudflare.m.upbound.io/v1alpha1"
KVNS_PATH = "/apis/%s/namespaces/%s/kvnamespaces/%s" % (GROUP, TARGET_NS, KV_NAMESPACE)
KV_PATH = "/apis/%s/namespaces/%s/kvs/%s" % (GROUP, TARGET_NS, KV_OBJECT)


def log(level, msg, **kw):
    print(json.dumps({"level": level, "msg": msg, **kw}), flush=True)


def request(path, method="GET", body=None, ctype=None, accept="application/json"):
    with open(os.path.join(SA_DIR, "token")) as f:
        token = f.read().strip()
    headers = {"Authorization": "Bearer " + token, "Accept": accept}
    if ctype:
        headers["Content-Type"] = ctype
    req = urllib.request.Request(API + path, data=body, method=method, headers=headers)
    ctx = ssl.create_default_context(cafile=os.path.join(SA_DIR, "ca.crt"))
    with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
        return json.loads(resp.read())


def get_or_none(path):
    try:
        return request(path)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise


def compact(doc):
    return json.dumps(doc, separators=(",", ":"))


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


def main():
    jwks = request("/openid/v1/jwks", accept="application/jwk-set+json, application/json")
    if not jwks.get("keys"):
        log("error", "API server returned an empty key set; not publishing it")
        return 1
    value = compact(jwks)
    kids = [k.get("kid") for k in jwks["keys"]]

    kvns = get_or_none(KVNS_PATH)
    namespace_id = ((kvns or {}).get("status", {}).get("atProvider", {}) or {}).get("id")
    if not namespace_id:
        log("warn", "KV namespace not ready yet; nothing published", object=KV_NAMESPACE)
        return 0

    current = get_or_none(KV_PATH)
    fp = ((current or {}).get("spec", {}).get("forProvider", {})) or {}
    if fp.get("value") == value and fp.get("namespaceId") == namespace_id and fp.get("keyName") == KEY_NAME:
        log("info", "published key set already current", kids=kids)
        return 0

    request(
        KV_PATH + "?fieldManager=%s&force=true" % FIELD_MANAGER,
        method="PATCH",
        body=json.dumps(desired(namespace_id, value)).encode(),
        ctype="application/apply-patch+yaml",
    )
    log("info", "published key set updated", kids=kids, created=current is None)
    return 0


if __name__ == "__main__":
    sys.exit(main())
