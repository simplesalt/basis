import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

sys.path.insert(0, "/scripts")

import finalizers
from client import Client

OVERRIDE_LABEL = "self-heal-timeout"
SKIP_KINDS = {
    ("", "persistentvolumes"),
    ("", "persistentvolumeclaims"),
    ("apiextensions.k8s.io", "customresourcedefinitions"),
}
DURATION_RE = re.compile(r"^(?P<value>[0-9]+)(?P<unit>[smhd]?)$")
UNIT_SECONDS = {"": 60, "s": 1, "m": 60, "h": 3600, "d": 86400}


def log(event, **fields):
    print(json.dumps({"event": event, **fields}, sort_keys=True), flush=True)


def default_timeout_seconds():
    try:
        return float(os.environ.get("DEFAULT_TIMEOUT_MINUTES", "15")) * 60
    except ValueError:
        return 15 * 60


def timeout_seconds(obj, default):
    raw = ((obj.get("metadata") or {}).get("labels") or {}).get(OVERRIDE_LABEL)
    if not raw:
        return default
    match = DURATION_RE.match(raw.strip())
    if not match:
        return default
    return int(match.group("value")) * UNIT_SECONDS[match.group("unit")]


def is_stateful(obj):
    return ((obj.get("metadata") or {}).get("labels") or {}).get("stateful") == "true"


def stateful_namespaces(client):
    names = set()
    for group, resource in (("", "persistentvolumeclaims"), ("postgresql.cnpg.io", "clusters")):
        items = client.list_resource(group, resource)
        if items is None:
            return None
        for obj in items:
            if is_stateful(obj):
                names.add(obj["metadata"].get("namespace"))
    for ns in client.list_resource("", "namespaces") or []:
        if is_stateful(ns):
            names.add(ns["metadata"]["name"])
    return names


def object_path(client, group, resource, obj):
    status, version, namespaced = client.resolve(group, resource)
    if status != "ok":
        return None
    base = "/apis/{}/{}".format(group, version) if group else "/api/{}".format(version)
    meta = obj["metadata"]
    if namespaced and meta.get("namespace"):
        return "{}/namespaces/{}/{}/{}".format(base, meta["namespace"], resource, meta["name"])
    return "{}/{}/{}".format(base, resource, meta["name"])


def clear_finalizers(client, path, resource_version):
    body = json.dumps({"metadata": {"finalizers": None, "resourceVersion": resource_version}}).encode()
    req = urllib.request.Request(
        client.base_url + path,
        data=body,
        headers={
            "Authorization": "Bearer " + client._token(),
            "Content-Type": "application/merge-patch+json",
            "Accept": "application/json",
        },
        method="PATCH",
    )
    with urllib.request.urlopen(req, context=client.ctx, timeout=20) as resp:
        resp.read()


def candidates(client):
    kinds = [k for k in finalizers.EXPLICIT_KINDS if k not in SKIP_KINDS]
    kinds.append(("", "namespaces"))
    for group in finalizers.PROACTIVE_GROUPS:
        for resource, _namespaced in client.group_resources(group) or []:
            kinds.append((group, resource))
    for group, resource in kinds:
        for obj in client.list_resource(group, resource) or []:
            yield group, resource, obj


def main():
    client = Client.in_cluster()
    now = datetime.now(timezone.utc)
    default = default_timeout_seconds()
    protected_namespaces = stateful_namespaces(client)
    if protected_namespaces is None:
        log("abort", reason="cannot list stateful objects", unverifiable=client.unverifiable)
        return 1

    cleared = 0
    failed = 0
    for group, resource, obj in candidates(client):
        meta = obj.get("metadata") or {}
        deleted_at = finalizers._parse_ts(meta.get("deletionTimestamp"))
        if deleted_at is None or not meta.get("finalizers"):
            continue
        age = (now - deleted_at).total_seconds()
        if age < timeout_seconds(obj, default):
            continue
        ident = {
            "group": group,
            "resource": resource,
            "namespace": meta.get("namespace"),
            "name": meta.get("name"),
            "finalizers": meta.get("finalizers"),
            "stuck_seconds": int(age),
        }
        if is_stateful(obj):
            log("skip-stateful", **ident)
            continue
        if meta.get("namespace") in protected_namespaces or (
            resource == "namespaces" and meta.get("name") in protected_namespaces
        ):
            log("skip-stateful-namespace", **ident)
            continue
        path = object_path(client, group, resource, obj)
        if path is None:
            continue
        try:
            clear_finalizers(client, path, meta.get("resourceVersion"))
            cleared += 1
            log("cleared", **ident)
        except urllib.error.HTTPError as exc:
            failed += 1
            log("clear-failed", status=exc.code, detail=exc.read().decode("utf-8", "replace")[:300], **ident)

    log("done", cleared=cleared, failed=failed, unverifiable=len(client.unverifiable))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
