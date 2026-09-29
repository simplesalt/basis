"""Crossplane health check: stuck managed resources and unhealthy providers.

Same interface as finalizers.check and flux.check so server.py can sum all
three unconditionally: `check(client, now) -> list` of problem dicts shaped
like finalizers.CATEGORY's ({category, severity, kind, apiVersion,
namespace, name, detail, ...}).

Two independent scans, both driven by what is actually registered/running in
the cluster rather than a hardcoded Kind list (same principle as
finalizers.py's PROACTIVE_GROUPS / group_resources walk):

1. Managed resources. Every Crossplane managed-resource CRD is discovered
   live from CustomResourceDefinitions whose spec.names.categories includes
   "managed" -- confirmed against the real cluster for both a cluster-scoped
   group (e.g. buckets.r2.upjet-cloudflare.upbound.io, scope: Cluster) and
   its namespaced ".m." twin (buckets.r2.upjet-cloudflare.m.upbound.io,
   scope: Namespaced); both carry categories [crossplane, managed,
   upjet-cloudflare]. Each CRD's objects are listed once, cluster-wide
   (namespace=None already means "every namespace" for a namespaced
   resource -- see client.py), not Kind by Kind. A stuck object is one
   whose status.conditions has Synced=False, Ready=False, or
   LastAsyncOperation=False (upjet/terraform-based providers -- observed as
   the condition an async Create/Update/Delete failure lands on) or
   AsyncOperation=False (older/alternate naming for the same signal, kept
   for safety); or one whose external-create annotations show an
   in-progress or failed create. Crossplane stamps
   crossplane.io/external-create-pending at the *start* of every async
   create, and later adds crossplane.io/external-create-succeeded or
   crossplane.io/external-create-failed when it finishes -- it never
   clears the pending annotation on success, so a finished create still
   carries a (now stale) pending annotation alongside its succeeded one.
   Telling a finished create apart from a stuck one mirrors
   crossplane-runtime's own rule for exactly this (v2.1.0
   pkg/meta/meta.go ExternalCreateIncomplete, used by the live Cloudflare
   providers): a create is incomplete only when pending is set and is
   strictly after both succeeded and failed (a missing succeeded/failed
   counts as zero, i.e. "never"; equal timestamps count as complete, not
   incomplete). So here: crossplane.io/external-create-pending is a
   problem only once it is strictly newer than both succeeded and failed
   *and* has sat there longer than the grace period below;
   crossplane.io/external-create-failed is a problem only when it is
   strictly newer than both pending and succeeded (still no grace period
   -- a completed failure is flagged as soon as it is the newest of the
   three). Whichever of the two is reported names whichever of
   succeeded/failed also exists, in its detail, for context. When an
   existing annotation's timestamp cannot be parsed, the comparison that
   would need it instead falls back to this check's older,
   single-annotation behavior for that category (grace-period-only for
   pending, on-sight for failed) rather than letting an unreadable
   annotation silently mask a real problem.

2. Providers and ProviderRevisions (pkg.crossplane.io). Checked against the
   real cluster (Crossplane v2.4.2): a Provider's own conditions are
   Installed/Healthy, but its ProviderRevision uses a different set --
   RevisionHealthy/RuntimeHealthy/RuntimeActive -- not Installed/Healthy.
   Rather than hardcode one naming scheme and miss the other, every
   condition among PACKAGE_HEALTH_CONDITIONS is checked on both Kinds and
   flagged if present with status != "True". Separately, every Provider
   whose own Healthy condition is True is cross-checked against its runtime
   Deployment in crossplane-system, because Provider.status can keep
   reporting Healthy=True with no pod actually running. The live link from
   Deployment to Provider is spec.selector.matchLabels["pkg.crossplane.io/provider"]
   (confirmed on every provider-*/upbound-*/wildbitca-* Deployment in
   crossplane-system) -- not the Deployment's own metadata.labels, which
   these package-manager-created Deployments do not carry at all, so a
   server-side label selector would silently match nothing (client.py's
   list_deployments takes no such parameter for exactly this reason). All
   Deployments in the namespace are listed once and matched client-side
   instead. An ownerReference to the
   Provider's active ProviderRevision is also present on these Deployments
   and would work as an alternative link, but the label is simpler to match
   directly and is what the provider's own runtime env vars
   (PROVIDER_NAME/REVISION_NAME) are themselves derived from.
"""

import os
from datetime import datetime, timezone

from finalizers import _format_duration, _parse_ts

CRD_GROUP = "apiextensions.k8s.io"
CRD_RESOURCE = "customresourcedefinitions"
MANAGED_CATEGORY = "managed"

PROVIDER_GROUP = "pkg.crossplane.io"
PROVIDER_RESOURCE = "providers"
PROVIDER_REVISION_RESOURCE = "providerrevisions"
PROVIDER_API_VERSION = "pkg.crossplane.io/v1"
PROVIDER_RUNTIME_NAMESPACE = "crossplane-system"
PROVIDER_LABEL = "pkg.crossplane.io/provider"

# Package (Provider/ProviderRevision) conditions that mean "this package is
# not fully up" when present and not True. Provider itself reports
# Installed/Healthy; ProviderRevision on this cluster's Crossplane (v2.4.2)
# reports RevisionHealthy/RuntimeHealthy/RuntimeActive instead -- see the
# module docstring. Checking the whole set on both Kinds covers either
# naming scheme without guessing which one a given Crossplane version uses.
PACKAGE_HEALTH_CONDITIONS = (
    "Installed",
    "Healthy",
    "RevisionHealthy",
    "RuntimeHealthy",
    "RuntimeActive",
)

CATEGORY_NOT_SYNCED = "crossplane-not-synced"
CATEGORY_NOT_READY = "crossplane-not-ready"
CATEGORY_ASYNC_FAILED = "crossplane-async-failed"
CATEGORY_CREATE_PENDING = "crossplane-create-pending"
CATEGORY_CREATE_FAILED = "crossplane-create-failed"
CATEGORY_PROVIDER_UNHEALTHY = "crossplane-provider-unhealthy"
CATEGORY_PROVIDER_RUNTIME_MISSING = "crossplane-provider-runtime-missing"

# Managed-resource condition type -> category, checked for status=="False"
# specifically (not merely != "True"): a fresh object legitimately sits at
# Unknown for a while, which is not itself a problem.
CONDITION_CATEGORIES = {
    "Synced": CATEGORY_NOT_SYNCED,
    "Ready": CATEGORY_NOT_READY,
    "LastAsyncOperation": CATEGORY_ASYNC_FAILED,
    "AsyncOperation": CATEGORY_ASYNC_FAILED,
}

EXTERNAL_CREATE_PENDING_ANNOTATION = "crossplane.io/external-create-pending"
EXTERNAL_CREATE_SUCCEEDED_ANNOTATION = "crossplane.io/external-create-succeeded"
EXTERNAL_CREATE_FAILED_ANNOTATION = "crossplane.io/external-create-failed"

# The epoch used for a missing succeeded/failed annotation in the pending/
# failed comparisons below -- matches crossplane-runtime's
# ExternalCreateIncomplete treating "unset" as zero, i.e. "never happened"
# (see module docstring), so it always loses to a real timestamp.
_ZERO_TIME = datetime.min.replace(tzinfo=timezone.utc)

# Severities are static per category (unlike finalizers.py's controller-
# state-derived severity) since there is no analogous "is something actively
# reconciling this" signal to grade on here. Async/create failures and
# provider-level problems are critical because they mean an external
# resource is out of sync with, or invisible to, its intended state; sync/
# ready/pending states are warning because they can still be mid-reconcile.
SEVERITY = {
    CATEGORY_NOT_SYNCED: "warning",
    CATEGORY_NOT_READY: "warning",
    CATEGORY_ASYNC_FAILED: "critical",
    CATEGORY_CREATE_PENDING: "warning",
    CATEGORY_CREATE_FAILED: "critical",
    CATEGORY_PROVIDER_UNHEALTHY: "critical",
    CATEGORY_PROVIDER_RUNTIME_MISSING: "critical",
}


def _create_pending_grace_minutes():
    try:
        return float(os.environ.get("CROSSPLANE_CREATE_PENDING_GRACE_MINUTES", "10"))
    except ValueError:
        return 10.0


def _condition_map(obj):
    conditions = {}
    for cond in obj.get("status", {}).get("conditions", []) or []:
        ctype = cond.get("type")
        if ctype:
            conditions[ctype] = cond
    return conditions


def _cause(cond):
    reason = cond.get("reason", "<no reason>")
    message = cond.get("message")
    return "{}: {}".format(reason, message) if message else reason


def _api_version_for(group, obj):
    api_version = obj.get("apiVersion")
    if api_version:
        return api_version
    return group if group else "v1"


def _problem(category, kind, api_version, namespace, name, detail):
    return {
        "category": category,
        "severity": SEVERITY[category],
        "kind": kind,
        "apiVersion": api_version,
        "namespace": namespace,
        "name": name,
        "detail": detail,
    }


def _is_managed_crd(crd):
    names = crd.get("spec", {}).get("names", {}) or {}
    return MANAGED_CATEGORY in (names.get("categories") or [])


def _managed_crd_targets(client):
    """Every (group, resource, kind) for a Crossplane managed-resource CRD
    registered in this cluster, one entry per CRD (cluster-scoped and
    namespaced ".m." groups alike -- see module docstring)."""
    crds = client.list_resource(CRD_GROUP, CRD_RESOURCE)
    if not crds:
        return []
    targets = []
    seen = set()
    for crd in crds:
        if not _is_managed_crd(crd):
            continue
        spec = crd.get("spec", {})
        group = spec.get("group", "")
        names = spec.get("names", {}) or {}
        resource = names.get("plural")
        if not resource:
            continue
        key = (group, resource)
        if key in seen:
            continue
        seen.add(key)
        targets.append((group, resource, names.get("kind")))
    return targets


def _managed_resource_problems(obj, group, kind, api_version, now, grace_seconds):
    problems = []
    metadata = obj.get("metadata", {})
    name = metadata.get("name", "<unknown>")
    namespace = metadata.get("namespace")
    conditions = _condition_map(obj)

    for ctype, category in CONDITION_CATEGORIES.items():
        cond = conditions.get(ctype)
        if cond is None or cond.get("status") != "False":
            continue
        problems.append(
            _problem(
                category,
                kind,
                api_version,
                namespace,
                name,
                "{}=False ({})".format(ctype, _cause(cond)),
            )
        )

    annotations = metadata.get("annotations") or {}

    pending_raw = annotations.get(EXTERNAL_CREATE_PENDING_ANNOTATION)
    succeeded_raw = annotations.get(EXTERNAL_CREATE_SUCCEEDED_ANNOTATION)
    failed_raw = annotations.get(EXTERNAL_CREATE_FAILED_ANNOTATION)

    pending_ts = _parse_ts(pending_raw) if pending_raw else None
    succeeded_ts = _parse_ts(succeeded_raw) if succeeded_raw else None
    failed_ts = _parse_ts(failed_raw) if failed_raw else None

    # An annotation that is present but fails to parse can't be placed on
    # the timeline at all -- it is neither "unset" (zero, see _ZERO_TIME)
    # nor a comparable instant. Folding it in as zero would let a garbled
    # succeeded/failed annotation silently clear a real pending-create or
    # create-failed problem, so any comparison that would need it instead
    # falls back to this check's older, single-annotation behavior for
    # that category (grace-period-only for pending, on-sight for failed).
    succeeded_unusable = succeeded_raw is not None and succeeded_ts is None
    failed_unusable = failed_raw is not None and failed_ts is None
    pending_unusable = pending_raw is not None and pending_ts is None

    if pending_raw and pending_ts is not None:
        if succeeded_unusable or failed_unusable:
            pending_incomplete = True
        else:
            pending_incomplete = pending_ts > max(
                succeeded_ts or _ZERO_TIME, failed_ts or _ZERO_TIME
            )
        if pending_incomplete:
            age_seconds = (now - pending_ts).total_seconds()
            if age_seconds >= grace_seconds:
                detail = "{} {} ({} ago, still pending)".format(
                    EXTERNAL_CREATE_PENDING_ANNOTATION,
                    pending_raw,
                    _format_duration(age_seconds),
                )
                if succeeded_raw:
                    detail += "; last succeeded {}".format(succeeded_raw)
                elif failed_raw:
                    detail += "; last failed {}".format(failed_raw)
                problems.append(
                    _problem(
                        CATEGORY_CREATE_PENDING,
                        kind,
                        api_version,
                        namespace,
                        name,
                        detail,
                    )
                )

    if failed_raw:
        if failed_ts is None or pending_unusable or succeeded_unusable:
            # Can't compare (failed's own time, or one of the others,
            # doesn't parse): keep the pre-comparison behavior of flagging
            # a completed failure as soon as it is seen.
            failed_is_latest = True
        else:
            failed_is_latest = failed_ts > max(
                pending_ts or _ZERO_TIME, succeeded_ts or _ZERO_TIME
            )
        if failed_is_latest:
            problems.append(
                _problem(
                    CATEGORY_CREATE_FAILED,
                    kind,
                    api_version,
                    namespace,
                    name,
                    "{} {}".format(EXTERNAL_CREATE_FAILED_ANNOTATION, failed_raw),
                )
            )

    return problems


def _scan_managed_resources(client, now, grace_seconds, problems):
    for group, resource, crd_kind in _managed_crd_targets(client):
        items = client.list_resource(group, resource, namespace=None)
        if not items:
            # None (failed) is already recorded to client.unverifiable by
            # list_resource itself; [] (verified-empty) needs no entry.
            continue
        for obj in items:
            api_version = _api_version_for(group, obj)
            kind = obj.get("kind") or crd_kind or resource
            problems.extend(
                _managed_resource_problems(obj, group, kind, api_version, now, grace_seconds)
            )


def _package_problems(obj, kind):
    problems = []
    name = obj.get("metadata", {}).get("name", "<unknown>")
    conditions = _condition_map(obj)
    for ctype in PACKAGE_HEALTH_CONDITIONS:
        cond = conditions.get(ctype)
        if cond is None or cond.get("status") == "True":
            continue
        problems.append(
            _problem(
                CATEGORY_PROVIDER_UNHEALTHY,
                kind,
                PROVIDER_API_VERSION,
                None,
                name,
                "{}={} ({})".format(ctype, cond.get("status"), _cause(cond)),
            )
        )
    return problems


def _provider_is_healthy(provider):
    healthy = _condition_map(provider).get("Healthy")
    return healthy is not None and healthy.get("status") == "True"


def _deployment_matches_provider(dep, provider_name):
    selector_labels = dep.get("spec", {}).get("selector", {}).get("matchLabels", {}) or {}
    return selector_labels.get(PROVIDER_LABEL) == provider_name


def _deployment_ready(dep):
    wanted = dep.get("spec", {}).get("replicas")
    if wanted is None:
        wanted = 1
    ready = dep.get("status", {}).get("readyReplicas") or 0
    return wanted > 0 and ready >= wanted


def _provider_runtime_problems(providers, deployments):
    problems = []
    if deployments is None:
        # Listing crossplane-system Deployments failed; already recorded to
        # client.unverifiable. Cannot cross-check, so don't guess.
        return problems

    for provider in providers:
        if not _provider_is_healthy(provider):
            continue
        name = provider.get("metadata", {}).get("name", "<unknown>")
        matches = [d for d in deployments if _deployment_matches_provider(d, name)]
        if not matches:
            problems.append(
                _problem(
                    CATEGORY_PROVIDER_RUNTIME_MISSING,
                    "Provider",
                    PROVIDER_API_VERSION,
                    None,
                    name,
                    "Healthy=True but no runtime Deployment found in {} matching {}={}".format(
                        PROVIDER_RUNTIME_NAMESPACE, PROVIDER_LABEL, name
                    ),
                )
            )
        elif not any(_deployment_ready(d) for d in matches):
            dep_names = ", ".join(
                d.get("metadata", {}).get("name", "<unknown>") for d in matches
            )
            problems.append(
                _problem(
                    CATEGORY_PROVIDER_RUNTIME_MISSING,
                    "Provider",
                    PROVIDER_API_VERSION,
                    None,
                    name,
                    "Healthy=True but its runtime Deployment ({}) has no ready replicas".format(
                        dep_names
                    ),
                )
            )
    return problems


def check(client, now):
    problems = []
    grace_seconds = _create_pending_grace_minutes() * 60

    _scan_managed_resources(client, now, grace_seconds, problems)

    providers = client.list_resource(PROVIDER_GROUP, PROVIDER_RESOURCE)
    for provider in providers or []:
        problems.extend(_package_problems(provider, "Provider"))

    revisions = client.list_resource(PROVIDER_GROUP, PROVIDER_REVISION_RESOURCE)
    for revision in revisions or []:
        problems.extend(_package_problems(revision, "ProviderRevision"))

    deployments = client.list_deployments(PROVIDER_RUNTIME_NAMESPACE)
    problems.extend(_provider_runtime_problems(providers or [], deployments))

    return problems
