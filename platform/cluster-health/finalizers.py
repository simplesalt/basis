"""Orphaned-finalizer check.

An object with a deletionTimestamp older than ORPHAN_AFTER_MINUTES and a
non-empty finalizer list (metadata.finalizers, or spec.finalizers for a
Namespace -- that is where the "kubernetes" finalizer actually lives) is
stuck: something was supposed to remove that finalizer and hasn't.

Entry point, per the parent Effort's request:

1. List Namespaces; for each Terminating one, check it for the same rule,
   then read its status.conditions for NamespaceContentRemaining /
   NamespaceFinalizersRemaining. NamespaceContentRemaining's message names
   the exact GroupResources still blocking it ("<resource>.<group> has N
   resource instances", straight from
   k8s.io/kubernetes/pkg/controller/namespace/deletion -- see
   _parse_content_remaining), so those get scanned inside that namespace.
2. Also scan cluster-scoped kinds that never show up in a namespace's own
   conditions: PersistentVolumes, CustomResourceDefinitions.
3. Also scan every Kind actually registered under the Flux and Crossplane
   groups the ClusterRole can read (platform/cluster-health.yaml),
   discovered live via Client.group_resources rather than a hardcoded Kind
   list, so a stuck object shows up even when no namespace is mid-delete at
   all (e.g. someone deleted a single HelmRelease directly).

For each stuck object, controller status is decided from the object's own
API group via controller-map.json -- never from the finalizer string, since
finalizers.fluxcd.io and finalizer.managedresource.crossplane.io are each
shared by many controllers. See client.py's module docstring for how a
failed/denied lookup surfaces (None, recorded to client.unverifiable) versus
a verified-absent one ([], no entry needed).
"""

import json
import os
import re
from datetime import datetime, timezone

CATEGORY = "orphaned-finalizer"

DEFAULT_CONTROLLER_MAP_PATH = os.path.join(os.path.dirname(__file__), "controller-map.json")
CONTROLLER_MAP_PATH = os.environ.get("CONTROLLER_MAP_PATH", DEFAULT_CONTROLLER_MAP_PATH)

# v1.NamespaceContentRemaining's message, built by
# ProcessContentTotals in pkg/controller/namespace/deletion/status_condition_utils.go:
#   fmt.Sprintf("%s.%s has %d resource instances", gvr.Resource, gvr.Group, n)
# joined with ", ". gvr.Group is "" for core resources, which leaves a bare
# trailing "." before " has" (e.g. "pods. has 3 resource instances").
_CONTENT_REMAINING_ITEM_RE = re.compile(r"^(?P<gvr>.+)\shas\s\d+\sresource\sinstances?$")

_BUILTIN_FINALIZER_NAMES = {"kubernetes", "orphan", "foregroundDeletion"}

CLUSTER_SCOPED_KINDS = [
    ("", "persistentvolumes"),
    ("apiextensions.k8s.io", "customresourcedefinitions"),
]

# Groups proactively walked in full (every Kind registered under them),
# independent of whether any namespace's conditions mention them. These are
# the two ecosystems this whole repo exists to drive (see README.md), so a
# stuck object here matters even with no namespace mid-delete.
PROACTIVE_GROUPS = [
    "kustomize.toolkit.fluxcd.io",
    "helm.toolkit.fluxcd.io",
    "source.toolkit.fluxcd.io",
    "pkg.crossplane.io",
    "apiextensions.crossplane.io",
]


def _is_builtin_finalizer(name):
    return name in _BUILTIN_FINALIZER_NAMES or name.startswith("kubernetes.io/")


def _load_controller_map(path):
    try:
        with open(path) as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return []
    return data.get("controllers", [])


_controller_map_cache = None


def _controller_map():
    global _controller_map_cache
    if _controller_map_cache is None:
        _controller_map_cache = _load_controller_map(CONTROLLER_MAP_PATH)
    return _controller_map_cache


def _group_matches(pattern, group):
    if pattern.startswith("*."):
        suffix = pattern[1:]  # keep the leading "."
        return group == pattern[2:] or group.endswith(suffix)
    return pattern == group


def _match_controller_entry(group):
    for entry in _controller_map():
        if _group_matches(entry.get("group", ""), group):
            return entry
    return None


def _parse_ts(raw):
    if raw is None:
        return None
    text = raw.rstrip("Z")
    if "." in text:
        date_part, frac = text.split(".", 1)
        frac = (frac + "000000")[:6]
        text = "{}.{}".format(date_part, frac)
        fmt = "%Y-%m-%dT%H:%M:%S.%f"
    else:
        fmt = "%Y-%m-%dT%H:%M:%S"
    try:
        return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _orphan_after_minutes():
    try:
        return float(os.environ.get("ORPHAN_AFTER_MINUTES", "15"))
    except ValueError:
        return 15.0


def _format_duration(seconds):
    seconds = int(seconds)
    hours, rem = divmod(seconds, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return "{}h{}m".format(hours, minutes)
    if minutes:
        return "{}m{}s".format(minutes, secs)
    return "{}s".format(secs)


def classify_controller(client, group, finalizers):
    if any(_is_builtin_finalizer(f) for f in finalizers):
        return "builtin"

    entry = _match_controller_entry(group)
    if entry is None:
        return "unknown"
    if entry.get("builtin"):
        return "builtin"

    deployments = client.list_deployments(
        entry["namespace"],
        match_labels=entry.get("matchLabels"),
        label_selector=entry.get("labelSelector"),
    )
    if deployments is None:
        return "unknown"
    if not deployments:
        return "missing"

    for dep in deployments:
        wanted = dep.get("spec", {}).get("replicas")
        if wanted is None:
            wanted = 1
        ready = dep.get("status", {}).get("readyReplicas") or 0
        if wanted > 0 and ready >= wanted:
            return "running"
    return "not-ready"


def _severity_for(controller):
    if controller in ("missing", "not-ready"):
        return "critical"
    return "warning"


def _object_finalizers(obj, kind):
    if kind == "Namespace":
        return list(obj.get("spec", {}).get("finalizers") or [])
    return list(obj.get("metadata", {}).get("finalizers") or [])


def _problem_for(client, obj, group, kind, api_version, now, threshold_seconds):
    metadata = obj.get("metadata", {})
    deletion_ts = _parse_ts(metadata.get("deletionTimestamp"))
    finalizers = _object_finalizers(obj, kind)
    if deletion_ts is None or not finalizers:
        return None

    age_seconds = (now - deletion_ts).total_seconds()
    if age_seconds < threshold_seconds:
        return None

    controller = classify_controller(client, group, finalizers)
    name = metadata.get("name", "<unknown>")
    namespace = metadata.get("namespace")

    return {
        "category": CATEGORY,
        "severity": _severity_for(controller),
        "kind": kind,
        "apiVersion": api_version,
        "namespace": namespace,
        "name": name,
        "controller": controller,
        "stuck_seconds": int(age_seconds),
        "detail": (
            "deletionTimestamp {} ({} ago); finalizers={}; controller={}".format(
                metadata.get("deletionTimestamp"),
                _format_duration(age_seconds),
                finalizers,
                controller,
            )
        ),
    }


def _api_version_for(group, obj):
    api_version = obj.get("apiVersion")
    if api_version:
        return api_version
    return group if group else "v1"


def _kind_for(group, resource, obj):
    kind = obj.get("kind")
    if kind:
        return kind
    return resource


def _scan_kind(client, group, resource, namespace, now, threshold_seconds, problems):
    items = client.list_resource(group, resource, namespace=namespace)
    if not items:
        return
    for obj in items:
        api_version = _api_version_for(group, obj)
        kind = _kind_for(group, resource, obj)
        problem = _problem_for(client, obj, group, kind, api_version, now, threshold_seconds)
        if problem is not None:
            problems.append(problem)


def _parse_content_remaining(message):
    """Yield (group, resource) for every GroupResource a
    NamespaceContentRemaining condition's message names as still blocking
    the namespace's deletion."""
    prefix = "Some resources are remaining: "
    body = message[len(prefix):] if message.startswith(prefix) else message
    for segment in body.split(", "):
        segment = segment.strip()
        if not segment:
            continue
        match = _CONTENT_REMAINING_ITEM_RE.match(segment)
        if not match:
            continue
        resource, _dot, group = match.group("gvr").partition(".")
        if resource:
            yield group, resource


def _is_terminating(ns):
    if ns.get("status", {}).get("phase") == "Terminating":
        return True
    return bool(ns.get("metadata", {}).get("deletionTimestamp"))


def check(client, now):
    problems = []
    threshold_seconds = _orphan_after_minutes() * 60

    namespaces = client.list_resource("", "namespaces") or []
    terminating = [ns for ns in namespaces if _is_terminating(ns)]

    scan_targets = set()
    for ns in terminating:
        problem = _problem_for(client, ns, "", "Namespace", "v1", now, threshold_seconds)
        if problem is not None:
            problems.append(problem)

        ns_name = ns.get("metadata", {}).get("name")
        for cond in ns.get("status", {}).get("conditions", []):
            if cond.get("type") != "NamespaceContentRemaining":
                continue
            if cond.get("status") != "True":
                continue
            for group, resource in _parse_content_remaining(cond.get("message", "")):
                scan_targets.add((group, resource, ns_name))

    for group, resource, namespace in scan_targets:
        _scan_kind(client, group, resource, namespace, now, threshold_seconds, problems)

    for group, resource in CLUSTER_SCOPED_KINDS:
        _scan_kind(client, group, resource, None, now, threshold_seconds, problems)

    for group in PROACTIVE_GROUPS:
        resources = client.group_resources(group)
        if not resources:
            continue
        for resource, _namespaced in resources:
            _scan_kind(client, group, resource, None, now, threshold_seconds, problems)

    return problems
