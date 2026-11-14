import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

sys.path.insert(0, "/scripts")

from client import ApiError, Client

IN_PROGRESS = "weave.works/kured-reboot-in-progress"
LOCK_ANNOTATION = os.environ.get("KURED_LOCK_ANNOTATION", "weave.works/kured-node-lock")
KURED_NAMESPACE = os.environ.get("KURED_NAMESPACE", "kured")
KURED_DAEMONSET = os.environ.get("KURED_DAEMONSET", "kured")


def log(event, **fields):
    print(json.dumps({"event": event, **fields}, sort_keys=True), flush=True)


def parse_ts(raw):
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


def settle_seconds():
    try:
        return float(os.environ.get("SETTLE_MINUTES", "5")) * 60
    except ValueError:
        return 300


def kured_locks(client):
    try:
        ds = client.get("/apis/apps/v1/namespaces/{}/daemonsets/{}".format(KURED_NAMESPACE, KURED_DAEMONSET))
    except ApiError as exc:
        if exc.status == 404:
            return {}
        raise
    raw = ((ds.get("metadata") or {}).get("annotations") or {}).get(LOCK_ANNOTATION)
    if not raw:
        return {}
    data = json.loads(raw)
    entries = data.get("locks") if isinstance(data.get("locks"), list) else [data]
    locks = {}
    for entry in entries:
        node_id = entry.get("nodeID")
        if not node_id:
            continue
        created = parse_ts(entry.get("created"))
        ttl = entry.get("TTL") or 0
        expires = created + timedelta(seconds=ttl / 1e9) if created and ttl else None
        locks[node_id] = {
            "expires": expires,
            "was_unschedulable": bool((entry.get("metadata") or {}).get("unschedulable")),
        }
    return locks


def ready_since(node):
    for cond in (node.get("status") or {}).get("conditions") or []:
        if cond.get("type") == "Ready":
            if cond.get("status") != "True":
                return None
            return parse_ts(cond.get("lastTransitionTime"))
    return None


def statuses(pod):
    status = pod.get("status") or {}
    return (status.get("initContainerStatuses") or []) + (status.get("containerStatuses") or [])


def pod_start_evidence(client, node_name, since):
    pods = client.get("/api/v1/pods", params={"fieldSelector": "spec.nodeName=" + node_name}).get("items") or []
    stuck = []
    started = []
    for pod in pods:
        meta = pod.get("metadata") or {}
        ident = "{}/{}".format(meta.get("namespace"), meta.get("name"))
        for cs in statuses(pod):
            if ((cs.get("state") or {}).get("waiting") or {}).get("reason") == "ContainerCreating":
                stuck.append(ident)
                break
        if (pod.get("spec") or {}).get("hostNetwork"):
            continue
        for cs in pod.get("status", {}).get("containerStatuses") or []:
            running_at = parse_ts(((cs.get("state") or {}).get("running") or {}).get("startedAt"))
            if running_at and running_at > since:
                started.append(ident)
                break
    return stuck, started


def uncordon(client, node_name, resource_version):
    body = json.dumps({
        "metadata": {"annotations": {IN_PROGRESS: None}, "resourceVersion": resource_version},
        "spec": {"unschedulable": None},
    }).encode()
    req = urllib.request.Request(
        client.base_url + "/api/v1/nodes/" + node_name,
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


def main():
    client = Client.in_cluster()
    now = datetime.now(timezone.utc)
    settle = settle_seconds()
    locks = kured_locks(client)
    uncordoned = 0
    held = 0
    failed = 0
    for node in client.get("/api/v1/nodes").get("items") or []:
        meta = node.get("metadata") or {}
        name = meta.get("name")
        if not (node.get("spec") or {}).get("unschedulable"):
            continue
        marked_at = parse_ts((meta.get("annotations") or {}).get(IN_PROGRESS))
        if marked_at is None:
            log("skip-not-kured", node=name)
            continue
        lock = locks.get(name)
        if lock and lock["was_unschedulable"]:
            log("skip-cordoned-before-kured", node=name)
            continue
        if lock and (lock["expires"] is None or lock["expires"] > now):
            log("skip-lock-held", node=name)
            continue
        since = ready_since(node)
        if since is None or since <= marked_at:
            held += 1
            log("hold-not-rebooted-ready", node=name, kured_marked_at=marked_at.isoformat())
            continue
        if (now - since).total_seconds() < settle:
            log("hold-settling", node=name, ready_since=since.isoformat())
            continue
        stuck, started = pod_start_evidence(client, name, since)
        if stuck or not started:
            held += 1
            log("hold-cannot-start-pods", node=name, stuck=stuck[:10], started=len(started))
            continue
        try:
            uncordon(client, name, meta.get("resourceVersion"))
            uncordoned += 1
            log("uncordoned", node=name, ready_since=since.isoformat(), started=started[:5])
        except urllib.error.HTTPError as exc:
            failed += 1
            log("uncordon-failed", node=name, status=exc.code, detail=exc.read().decode("utf-8", "replace")[:300])

    log("done", uncordoned=uncordoned, held=held, failed=failed)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
