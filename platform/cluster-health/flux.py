"""Unhealthy Flux reconciliation check.

Same interface as finalizers.check and crossplane.check so server.py can sum
all three unconditionally: `check(client, now) -> list` of problem dicts
shaped like finalizers.CATEGORY's ({category, severity, kind, apiVersion,
namespace, name, detail, ...}).

Covers, per the parent Effort's request:

* Kustomizations (kustomize.toolkit.fluxcd.io): Ready not True
  (flux-not-ready); Reconciling=True with reason ProgressingWithRetry
  (flux-retrying); status.observedGeneration behind metadata.generation
  (flux-generation-lag); a requested reconcile
  (annotation reconcile.fluxcd.io/requestedAt) not yet reflected in
  status.lastHandledReconcileAt after a short grace (flux-reconcile-
  request-unhandled); status.history holding failed entries
  (lastReconciledStatus != ReconciliationSucceeded) alongside a current
  success -- flapping (flux-history-failures).
* HelmReleases (helm.toolkit.fluxcd.io): Ready not True (flux-not-ready);
  status.history entries whose status is failed or one of the
  pending-install / pending-upgrade / pending-rollback / uninstalling
  transients (flux-history-failures), reported even when Ready is
  currently True -- a release can recover and still be worth knowing it
  flapped.
* Sources -- GitRepository / HelmRepository / OCIRepository / Bucket
  (source.toolkit.fluxcd.io): Ready not True (flux-not-ready);
  status.artifact.lastUpdateTime older than SOURCE_STALE_MULTIPLIER times
  spec.interval (flux-source-stale).
* spec.suspend: true on any of the six kinds above (flux-suspended).
* Objects listed in a Kustomization's status.inventory.entries that carry
  the annotation kustomize.toolkit.fluxcd.io/reconcile: disabled
  (flux-reconcile-disabled) -- they are excluded from that Kustomization's
  drift correction, which is worth surfacing even though it is not itself
  a failure.

Severity follows finalizers.py's lead: critical for a hard Ready=False/
stuck signal (flux-not-ready), warning for everything else (retrying,
generation lag, an unhandled reconcile request, history/flapping,
staleness, suspend, a disabled inventory entry) -- signals that something
needs attention but nothing is currently on fire.

API calls stay bounded the same way finalizers.py's PROACTIVE_GROUPS scan
does: each (group, resource) is listed once, cluster-wide
(namespace=None), and reused. The one exception is the inventory-disabled
check, which by nature names arbitrary Kinds it did not otherwise list
(anything a Kustomization manages) -- those are still grouped by (group,
resource) and listed once per pair rather than once per inventory entry,
and Secrets are never looked up at all (this service is not granted
Secret read; see platform/cluster-health.yaml), not even attempted, so
they never appear in client.unverifiable either.

Resolving a Kind (e.g. "HorizontalPodAutoscaler") to its list resource
name (e.g. "horizontalpodautoscalers") for the inventory check is a
best-effort English pluralization (see _pluralize_kind) with a small
override table for known irregulars (Endpoints). client.py's discovery
cache maps resource name -> namespaced, not Kind -> resource name, and
extending it to do the reverse is out of this module's scope; a
mis-pluralized Kind simply fails to list (or lists the wrong thing, which
finds no matching id and reports nothing for it) rather than crashing.
"""

import re
from datetime import datetime, timezone

CATEGORY_NOT_READY = "flux-not-ready"
CATEGORY_RETRYING = "flux-retrying"
CATEGORY_GENERATION_LAG = "flux-generation-lag"
CATEGORY_REQUEST_UNHANDLED = "flux-reconcile-request-unhandled"
CATEGORY_HISTORY_FAILURES = "flux-history-failures"
CATEGORY_SOURCE_STALE = "flux-source-stale"
CATEGORY_SUSPENDED = "flux-suspended"
CATEGORY_RECONCILE_DISABLED = "flux-reconcile-disabled"

REQUESTED_AT_ANNOTATION = "reconcile.fluxcd.io/requestedAt"
RECONCILE_ANNOTATION = "kustomize.toolkit.fluxcd.io/reconcile"

REQUEST_GRACE_SECONDS = 5 * 60
SOURCE_STALE_MULTIPLIER = 5

KUSTOMIZATION_GROUP = "kustomize.toolkit.fluxcd.io"
HELMRELEASE_GROUP = "helm.toolkit.fluxcd.io"
SOURCE_GROUP = "source.toolkit.fluxcd.io"

KUSTOMIZATION_RESOURCE = "kustomizations"
HELMRELEASE_RESOURCE = "helmreleases"

# (resource, Kind) for every source.toolkit.fluxcd.io kind this check walks.
SOURCE_KINDS = [
    ("gitrepositories", "GitRepository"),
    ("helmrepositories", "HelmRepository"),
    ("ocirepositories", "OCIRepository"),
    ("buckets", "Bucket"),
]

# helm.sh/helm/v3/pkg/release.Status values that mean "not a clean deploy".
HELM_BAD_STATUSES = {
    "failed",
    "pending-install",
    "pending-upgrade",
    "pending-rollback",
    "uninstalling",
}

# Never even attempt to list these Kinds -- this service has no Secret
# read permission by design (platform/cluster-health.yaml), so an
# inventory entry naming one is skipped silently rather than turned into
# an unverifiable/RBAC-denied entry.
_INVENTORY_SKIP_KINDS = {"Secret"}

_KIND_TO_RESOURCE_OVERRIDES = {
    "Endpoints": "endpoints",
}

_DURATION_RE = re.compile(r"(\d+(?:\.\d+)?)(ms|h|m|s)")


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


def _format_duration(seconds):
    seconds = int(seconds)
    hours, rem = divmod(seconds, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return "{}h{}m".format(hours, minutes)
    if minutes:
        return "{}m{}s".format(minutes, secs)
    return "{}s".format(secs)


def _duration_seconds(text):
    """Parse a Go-style duration string (e.g. "10m", "1h30m", "45s") into
    seconds, or None if it is missing or unparseable."""
    if not text:
        return None
    total = 0.0
    matched = False
    for value, unit in _DURATION_RE.findall(text):
        matched = True
        n = float(value)
        if unit == "h":
            total += n * 3600
        elif unit == "m":
            total += n * 60
        elif unit == "s":
            total += n
        elif unit == "ms":
            total += n / 1000
    return total if matched else None


def _get_condition(obj, cond_type):
    for cond in (obj.get("status", {}) or {}).get("conditions", []) or []:
        if cond.get("type") == cond_type:
            return cond
    return None


def _api_version(group, obj):
    api_version = obj.get("apiVersion")
    if api_version:
        return api_version
    return group if group else "v1"


def _base_problem(category, severity, kind, api_version, namespace, name, detail, **extra):
    problem = {
        "category": category,
        "severity": severity,
        "kind": kind,
        "apiVersion": api_version,
        "namespace": namespace,
        "name": name,
        "detail": detail,
    }
    problem.update(extra)
    return problem


def _pluralize_kind(kind):
    if kind in _KIND_TO_RESOURCE_OVERRIDES:
        return _KIND_TO_RESOURCE_OVERRIDES[kind]
    lower = kind.lower()
    if lower.endswith("y") and len(lower) > 1 and lower[-2] not in "aeiou":
        return lower[:-1] + "ies"
    if lower.endswith(("s", "x", "z", "ch", "sh")):
        return lower + "es"
    return lower + "s"


def _parse_inventory_id(entry_id):
    """"<namespace>_<name>_<group>_<Kind>" -> (namespace or None, name,
    group, kind), or None if it isn't shaped that way. Namespace, name and
    group never contain "_" in a real cluster (DNS-1123 names, dotted
    group names), so a plain split is safe."""
    parts = (entry_id or "").split("_")
    if len(parts) != 4:
        return None
    namespace, name, group, kind = parts
    if not name or not kind:
        return None
    return (namespace or None, name, group, kind)


def _ready_not_true_problem(group, kind, obj):
    cond = _get_condition(obj, "Ready")
    status = cond.get("status") if cond else None
    if status == "True":
        return None
    metadata = obj.get("metadata", {})
    reason = cond.get("reason") if cond else "NoReadyCondition"
    message = cond.get("message") if cond else "no Ready condition reported"
    return _base_problem(
        CATEGORY_NOT_READY,
        "critical",
        kind,
        _api_version(group, obj),
        metadata.get("namespace"),
        metadata.get("name", "<unknown>"),
        "Ready={} reason={} message={}".format(status, reason, message),
    )


def _suspended_problem(group, kind, obj):
    spec = obj.get("spec", {}) or {}
    if spec.get("suspend") is not True:
        return None
    metadata = obj.get("metadata", {})
    return _base_problem(
        CATEGORY_SUSPENDED,
        "warning",
        kind,
        _api_version(group, obj),
        metadata.get("namespace"),
        metadata.get("name", "<unknown>"),
        "spec.suspend=true",
    )


def _check_kustomization(obj, now, problems):
    metadata = obj.get("metadata", {})
    spec = obj.get("spec", {}) or {}
    status = obj.get("status", {}) or {}
    namespace = metadata.get("namespace")
    name = metadata.get("name", "<unknown>")
    api_version = _api_version(KUSTOMIZATION_GROUP, obj)

    problem = _ready_not_true_problem(KUSTOMIZATION_GROUP, "Kustomization", obj)
    if problem is not None:
        problems.append(problem)

    problem = _suspended_problem(KUSTOMIZATION_GROUP, "Kustomization", obj)
    if problem is not None:
        problems.append(problem)

    reconciling = _get_condition(obj, "Reconciling")
    if (
        reconciling is not None
        and reconciling.get("status") == "True"
        and reconciling.get("reason") == "ProgressingWithRetry"
    ):
        problems.append(
            _base_problem(
                CATEGORY_RETRYING,
                "warning",
                "Kustomization",
                api_version,
                namespace,
                name,
                "Reconciling=True reason=ProgressingWithRetry: {}".format(
                    reconciling.get("message") or "retrying after a failed apply"
                ),
            )
        )

    generation = metadata.get("generation")
    observed = status.get("observedGeneration")
    if (
        isinstance(generation, int)
        and isinstance(observed, int)
        and observed < generation
    ):
        problems.append(
            _base_problem(
                CATEGORY_GENERATION_LAG,
                "warning",
                "Kustomization",
                api_version,
                namespace,
                name,
                "status.observedGeneration={} is behind metadata.generation={}".format(
                    observed, generation
                ),
            )
        )

    requested_at = (metadata.get("annotations") or {}).get(REQUESTED_AT_ANNOTATION)
    handled_at = status.get("lastHandledReconcileAt")
    if requested_at and requested_at != handled_at:
        requested_ts = _parse_ts(requested_at)
        if requested_ts is not None:
            age_seconds = (now - requested_ts).total_seconds()
            if age_seconds > REQUEST_GRACE_SECONDS:
                problems.append(
                    _base_problem(
                        CATEGORY_REQUEST_UNHANDLED,
                        "warning",
                        "Kustomization",
                        api_version,
                        namespace,
                        name,
                        "requestedAt={} ({} ago) is not yet reflected in "
                        "status.lastHandledReconcileAt={}".format(
                            requested_at, _format_duration(age_seconds), handled_at
                        ),
                    )
                )

    history = status.get("history") or []
    failed = [
        h
        for h in history
        if h.get("lastReconciledStatus")
        and h.get("lastReconciledStatus") != "ReconciliationSucceeded"
    ]
    succeeded = [h for h in history if h.get("lastReconciledStatus") == "ReconciliationSucceeded"]
    if failed and succeeded:
        times = sorted(t for t in (h.get("lastReconciledAt") for h in failed) if t)
        first_time = times[0] if times else None
        last_time = times[-1] if times else None
        problems.append(
            _base_problem(
                CATEGORY_HISTORY_FAILURES,
                "warning",
                "Kustomization",
                api_version,
                namespace,
                name,
                "{} failed reconciliations in status.history alongside a current "
                "success (flapping); first={} last={}".format(
                    len(failed), first_time, last_time
                ),
                count=len(failed),
                first_time=first_time,
                last_time=last_time,
            )
        )


def _check_helmrelease(obj, now, problems):
    metadata = obj.get("metadata", {})
    status = obj.get("status", {}) or {}
    namespace = metadata.get("namespace")
    name = metadata.get("name", "<unknown>")
    api_version = _api_version(HELMRELEASE_GROUP, obj)

    problem = _ready_not_true_problem(HELMRELEASE_GROUP, "HelmRelease", obj)
    if problem is not None:
        problems.append(problem)

    problem = _suspended_problem(HELMRELEASE_GROUP, "HelmRelease", obj)
    if problem is not None:
        problems.append(problem)

    history = status.get("history") or []
    bad = [h for h in history if h.get("status") in HELM_BAD_STATUSES]
    if bad:
        times = sorted(t for t in (h.get("lastDeployed") or h.get("firstDeployed") for h in bad) if t)
        first_time = times[0] if times else None
        last_time = times[-1] if times else None
        statuses = sorted({h.get("status") for h in bad})
        problems.append(
            _base_problem(
                CATEGORY_HISTORY_FAILURES,
                "warning",
                "HelmRelease",
                api_version,
                namespace,
                name,
                "{} release history entries with status in {} (first={} "
                "last={}); reported even though Ready may currently be True".format(
                    len(bad), statuses, first_time, last_time
                ),
                count=len(bad),
                first_time=first_time,
                last_time=last_time,
            )
        )


def _check_source(kind, obj, now, problems):
    metadata = obj.get("metadata", {})
    spec = obj.get("spec", {}) or {}
    status = obj.get("status", {}) or {}
    namespace = metadata.get("namespace")
    name = metadata.get("name", "<unknown>")
    api_version = _api_version(SOURCE_GROUP, obj)

    problem = _ready_not_true_problem(SOURCE_GROUP, kind, obj)
    if problem is not None:
        problems.append(problem)

    problem = _suspended_problem(SOURCE_GROUP, kind, obj)
    if problem is not None:
        problems.append(problem)

    artifact = status.get("artifact")
    interval_seconds = _duration_seconds(spec.get("interval"))
    if artifact and interval_seconds:
        last_update = _parse_ts(artifact.get("lastUpdateTime"))
        if last_update is not None:
            age_seconds = (now - last_update).total_seconds()
            threshold_seconds = interval_seconds * SOURCE_STALE_MULTIPLIER
            if age_seconds > threshold_seconds:
                problems.append(
                    _base_problem(
                        CATEGORY_SOURCE_STALE,
                        "warning",
                        kind,
                        api_version,
                        namespace,
                        name,
                        "artifact last updated {} ago, more than {}x spec.interval "
                        "({})".format(
                            _format_duration(age_seconds),
                            SOURCE_STALE_MULTIPLIER,
                            spec.get("interval"),
                        ),
                    )
                )


def _check_inventory_disabled(client, kustomizations, problems):
    targets = []  # (group, resource, namespace, name, kind, ks_namespace, ks_name)
    for ks in kustomizations:
        ks_metadata = ks.get("metadata", {})
        ks_namespace = ks_metadata.get("namespace")
        ks_name = ks_metadata.get("name", "<unknown>")
        inventory = (ks.get("status", {}) or {}).get("inventory") or {}
        for entry in inventory.get("entries") or []:
            parsed = _parse_inventory_id(entry.get("id", ""))
            if parsed is None:
                continue
            namespace, name, group, kind = parsed
            if kind in _INVENTORY_SKIP_KINDS:
                continue
            resource = _pluralize_kind(kind)
            targets.append((group, resource, namespace, name, kind, ks_namespace, ks_name))

    if not targets:
        return

    # List each (group, resource) once, cluster-wide, and reuse -- never
    # fetch an inventory object one at a time.
    lookups = {}
    for group, resource in sorted({(t[0], t[1]) for t in targets}):
        items = client.list_resource(group, resource, namespace=None)
        if items is None:
            continue  # failure already recorded on client.unverifiable
        lookup = {}
        for obj in items:
            obj_metadata = obj.get("metadata", {})
            lookup[(obj_metadata.get("namespace"), obj_metadata.get("name"))] = obj
        lookups[(group, resource)] = lookup

    for group, resource, namespace, name, kind, ks_namespace, ks_name in targets:
        lookup = lookups.get((group, resource))
        if lookup is None:
            continue
        obj = lookup.get((namespace, name))
        if obj is None:
            continue
        annotations = (obj.get("metadata", {}) or {}).get("annotations") or {}
        if annotations.get(RECONCILE_ANNOTATION) != "disabled":
            continue
        problems.append(
            _base_problem(
                CATEGORY_RECONCILE_DISABLED,
                "warning",
                kind,
                _api_version(group, obj),
                namespace,
                name,
                "annotation {}=disabled; excluded from Kustomization {}/{}'s drift "
                "correction".format(RECONCILE_ANNOTATION, ks_namespace, ks_name),
                kustomization_namespace=ks_namespace,
                kustomization_name=ks_name,
            )
        )


def check(client, now):
    problems = []

    kustomizations = client.list_resource(KUSTOMIZATION_GROUP, KUSTOMIZATION_RESOURCE, namespace=None)
    if kustomizations:
        for obj in kustomizations:
            _check_kustomization(obj, now, problems)

    helmreleases = client.list_resource(HELMRELEASE_GROUP, HELMRELEASE_RESOURCE, namespace=None)
    if helmreleases:
        for obj in helmreleases:
            _check_helmrelease(obj, now, problems)

    for resource, kind in SOURCE_KINDS:
        items = client.list_resource(SOURCE_GROUP, resource, namespace=None)
        if not items:
            continue
        for obj in items:
            _check_source(kind, obj, now, problems)

    if kustomizations:
        _check_inventory_disabled(client, kustomizations, problems)

    return problems
