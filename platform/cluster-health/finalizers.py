"""Orphaned-finalizer check.

An object with a deletionTimestamp older than ORPHAN_AFTER_MINUTES and a
non-empty finalizer list (metadata.finalizers, or spec.finalizers for a
Namespace -- that is where the "kubernetes" finalizer actually lives) is
stuck: something was supposed to remove that finalizer and hasn't.

Entry point. The requirement this check exists to meet is "every object
stuck deleting on a finalizer is listed" -- not just one sitting inside a
Terminating namespace, so the scan has two halves:

1. List Namespaces; for each Terminating one, check it for the same rule,
   then read its status.conditions for NamespaceContentRemaining /
   NamespaceFinalizersRemaining. NamespaceContentRemaining's message names
   the exact GroupResources still blocking it ("<resource>.<group> has N
   resource instances", straight from
   k8s.io/kubernetes/pkg/controller/namespace/deletion -- see
   _parse_content_remaining), so those get scanned inside that namespace.
   This is the only way to see a stuck object of a Kind the ClusterRole
   does not grant (still recorded to client.unverifiable, same as always).
2. Scan every listable resource type in every API group the ClusterRole
   (platform/cluster-health.yaml) actually grants, cluster-wide (one list
   per resource type, namespace=None already means "every namespace" for a
   namespaced resource -- see client.py), regardless of whether any
   namespace is mid-delete at all -- so a stuck CNPG Cluster, FluentBit
   Kind, cert-manager Certificate, Kyverno policy, Pod, PVC or Deployment
   in an otherwise-Active namespace is found too, not just Flux and
   Crossplane objects. Two constants describe this, both mirroring the
   ClusterRole's own rules and needing to stay in sync with it by hand
   (nothing here parses cluster-health.yaml at runtime -- it isn't shipped
   into the pod, only the scripts are):

   * EXPLICIT_KINDS -- every resource the ClusterRole names one by one, by
     group and resource, rather than via a "*" wildcard on the whole group
     (core Pods/PVs/PVCs/ConfigMaps/Services/ServiceAccounts, apps
     Deployments, apiextensions.k8s.io CRDs, batch Jobs/CronJobs,
     coordination.k8s.io Leases, networking.k8s.io NetworkPolicies,
     rbac.authorization.k8s.io Roles/RoleBindings/ClusterRoles/
     ClusterRoleBindings, fluxcd.controlplane.io FluxInstances -- never
     Secrets: the ClusterRole does not grant the core group's wildcard, so
     Secret access is never even requested).
   * PROACTIVE_GROUPS -- every API group the ClusterRole grants
     resources: ["*"] on, walked in full via Client.group_resources
     (discovered live, so a Kind is never missed by not being on a
     hand-maintained list) rather than a hardcoded Kind list.

   Namespaces themselves are not repeated here: every Namespace is already
   listed and checked in step 1 above.

A (group, resource) the full scan in step 2 already covers is not also
listed namespace-scoped for step 1's condition-named targets -- client.py's
per-request list cache would make the second call free of a duplicate
network round trip regardless, but skipping it here keeps this module's own
intent legible (see check()'s `scanned` set).

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

# controller-map.json's "labelSelector" entries use exactly this one shape:
# `key in (value,value,...)`, e.g. for a group several Deployments could
# service (see _deployment_matches_entry).
_IN_SELECTOR_RE = re.compile(r"^\s*(\S+)\s+in\s*\(([^)]*)\)\s*$")

# Every resource platform/cluster-health.yaml's ClusterRole names explicitly
# by group and resource (not via a "*" resources wildcard on the whole
# group -- those are PROACTIVE_GROUPS below). Namespaces is deliberately not
# here -- check() already lists every Namespace for step 1's Terminating
# walk, so listing it again here would be redundant. Secrets is deliberately
# not here either: the ClusterRole never grants it.
EXPLICIT_KINDS = [
    ("", "pods"),
    ("", "persistentvolumes"),
    ("", "persistentvolumeclaims"),
    ("", "configmaps"),
    ("", "services"),
    ("", "serviceaccounts"),
    ("apps", "deployments"),
    ("apiextensions.k8s.io", "customresourcedefinitions"),
    ("batch", "jobs"),
    ("batch", "cronjobs"),
    ("coordination.k8s.io", "leases"),
    ("networking.k8s.io", "networkpolicies"),
    ("rbac.authorization.k8s.io", "roles"),
    ("rbac.authorization.k8s.io", "rolebindings"),
    ("rbac.authorization.k8s.io", "clusterroles"),
    ("rbac.authorization.k8s.io", "clusterrolebindings"),
    ("fluxcd.controlplane.io", "fluxinstances"),
]

# Every API group platform/cluster-health.yaml's ClusterRole grants
# resources: ["*"], verbs: [get, list] on, walked in full (every Kind
# Client.group_resources discovers under it) independent of whether any
# namespace's conditions mention them -- so a stuck object here matters
# even with no namespace mid-delete. Kept in the ClusterRole's own order/
# grouping (Flux; Crossplane core + managed-resource groups; other
# operators this repo installs) to make the two easy to eyeball against
# each other.
PROACTIVE_GROUPS = [
    # Flux
    "kustomize.toolkit.fluxcd.io",
    "helm.toolkit.fluxcd.io",
    "source.toolkit.fluxcd.io",
    # Crossplane core + managed-resource groups
    "pkg.crossplane.io",
    "apiextensions.crossplane.io",
    "cloudplatform.gcp.m.upbound.io",
    "cloudplatform.gcp.upbound.io",
    "gcp.m.upbound.io",
    "gcp.upbound.io",
    "dns.upjet-cloudflare.m.upbound.io",
    "dns.upjet-cloudflare.upbound.io",
    "r2.upjet-cloudflare.m.upbound.io",
    "r2.upjet-cloudflare.upbound.io",
    "upjet-cloudflare.m.upbound.io",
    "upjet-cloudflare.upbound.io",
    "workers.upjet-cloudflare.m.upbound.io",
    "workers.upjet-cloudflare.upbound.io",
    "zero.upjet-cloudflare.m.upbound.io",
    "zero.upjet-cloudflare.upbound.io",
    # Other operators this repo installs
    "fluentbit.fluent.io",
    "postgresql.cnpg.io",
    "cert-manager.io",
    "kyverno.io",
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


def _deployment_labels(dep):
    """The labels that actually identify what a Deployment's pods run:
    spec.template.metadata.labels, falling back to spec.selector.matchLabels
    for a Deployment whose template happens to omit a key its selector still
    carries. Never metadata.labels -- several real Deployments controller-map.json
    matches against (every Crossplane provider package runtime, confirmed
    live) have no top-level labels at all, and others that do have some
    still omit the specific key an entry needs (the Flux controllers carry
    `app=<name>` only in the template/selector, not at the top level)."""
    template_labels = dep.get("spec", {}).get("template", {}).get("metadata", {}).get("labels")
    if template_labels:
        return template_labels
    return dep.get("spec", {}).get("selector", {}).get("matchLabels", {}) or {}


def _parse_in_selector(expr):
    """Parse a `key in (a,b,c)` label-selector expression -- the only shape
    controller-map.json's "labelSelector" entries use -- into (key,
    {value, ...}). Returns None if `expr` is not that shape."""
    match = _IN_SELECTOR_RE.match(expr or "")
    if not match:
        return None
    key = match.group(1)
    values = {v.strip() for v in match.group(2).split(",") if v.strip()}
    return key, values


def _deployment_matches_entry(dep, entry):
    labels = _deployment_labels(dep)
    label_selector = entry.get("labelSelector")
    if label_selector:
        parsed = _parse_in_selector(label_selector)
        if parsed is None:
            return False
        key, values = parsed
        return labels.get(key) in values
    match_labels = entry.get("matchLabels") or {}
    return all(labels.get(k) == v for k, v in match_labels.items())


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

    # Listed once per namespace and cached by client.list_deployments for
    # the lifetime of this check run; matched client-side below rather than
    # via a server-side label selector (see _deployment_labels).
    deployments = client.list_deployments(entry["namespace"])
    if deployments is None:
        return "unknown"

    matching = [dep for dep in deployments if _deployment_matches_entry(dep, entry)]
    if not matching:
        return "missing"

    for dep in matching:
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


def _api_version_for(client, group, resource, obj):
    api_version = obj.get("apiVersion")
    if api_version:
        return api_version
    getter = getattr(client, "api_version_for", None)
    resolved = getter(group, resource) if getter else None
    return resolved or (group if group else "v1")


def _kind_for(client, group, resource, obj):
    kind = obj.get("kind")
    if kind:
        return kind
    getter = getattr(client, "kind_for", None)
    resolved = getter(group, resource) if getter else None
    return resolved or resource


def _scan_kind(client, group, resource, namespace, now, threshold_seconds, problems):
    items = client.list_resource(group, resource, namespace=namespace)
    if not items:
        return
    for obj in items:
        api_version = _api_version_for(client, group, resource, obj)
        kind = _kind_for(client, group, resource, obj)
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

    # Full scan: every listable resource type in every group the ClusterRole
    # grants, cluster-wide, regardless of any namespace's own conditions.
    # `scanned` tracks each (group, resource) this covers so the
    # condition-named targets below skip re-listing one namespace-scoped
    # (client.py's list cache would make that free of a duplicate network
    # call anyway, but a cluster-wide list already has every namespace's
    # objects, so there is nothing left for a namespace-scoped repeat to
    # find).
    scanned = set()

    for group, resource in EXPLICIT_KINDS:
        _scan_kind(client, group, resource, None, now, threshold_seconds, problems)
        scanned.add((group, resource))

    for group in PROACTIVE_GROUPS:
        resources = client.group_resources(group)
        if not resources:
            continue
        for resource, _namespaced in resources:
            _scan_kind(client, group, resource, None, now, threshold_seconds, problems)
            scanned.add((group, resource))

    # Kinds named by a Terminating namespace's own conditions that the
    # ClusterRole does not grant (so the full scan above never touched
    # them) still get scanned inside that namespace, same as always -- a
    # denied attempt still lands on client.unverifiable.
    for group, resource, namespace in scan_targets:
        if (group, resource) in scanned:
            continue
        _scan_kind(client, group, resource, namespace, now, threshold_seconds, problems)

    return problems
