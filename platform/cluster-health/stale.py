"""Stuck-Ready and webhook-backend health checks.

Same interface as finalizers.check, flux.check and crossplane.check so
server.py can sum all of them unconditionally: `check(client, now) -> list`
of problem dicts shaped like flux.py's `_base_problem`'s ({category,
severity, kind, apiVersion, namespace, name, detail, ...}).

Two independent scans:

1. not-ready-long. An object whose Ready condition (Available, for a
   Deployment -- apps Deployments never carry a Ready condition, only
   Available/Progressing) has been anything but True for longer than
   NOT_READY_AFTER_HOURS is worth surfacing on its own, separate from
   finalizers.py's stuck-deleting scan and flux.py/crossplane.py's
   controller-specific signals -- this is the generic "something has been
   broken a while" net that catches whatever those miss, e.g. a
   cert-manager ClusterIssuer or a Crossplane-managed DNS Record sitting on
   Ready=False for weeks with nothing else watching it.

   Walked over exactly the same object universe finalizers.py's widened
   scan already lists -- EXPLICIT_KINDS plus every resource of every
   PROACTIVE_GROUPS group, both imported from finalizers.py rather than
   redeclared, so client.py's per-request list cache (see its module
   docstring) serves this scan's lists from the same cached calls
   finalizers.check already made, never a second round trip -- plus Nodes
   (group "", resource "nodes"), which neither of those two lists covers
   and which this module adds on its own.

   Confirmed live (2026-09-28): a Ready-not-True-over-24h rule catches
   ClusterIssuer simplesalt (cert-manager.io/v1, Ready=False reason
   InvalidSolver since 2026-08-20) and Record info-simplesalt-company
   (dns.upjet-cloudflare.upbound.io, Ready=False reason Creating since
   2026-08-21) -- both real, both otherwise invisible to finalizers.py (no
   deletionTimestamp), flux.py (not a Flux kind) or crossplane.py's
   condition set (Synced/Ready/AsyncOperation are checked for status==False
   specifically, not aged). The only not-Ready Pods on this cluster are
   Succeeded Job pods (reason PodCompleted) -- explicitly skipped below, by
   phase, since a completed Job pod's Ready=False is normal and permanent.
   DaemonSet pods report through the DaemonSet's own Pods, not through any
   condition on the DaemonSet object itself -- DaemonSets carry no
   conditions at all, so they simply never match a Ready/Available lookup
   here and need no special-casing.

2. webhook-no-backend. Every admissionregistration.k8s.io
   ValidatingWebhookConfiguration/MutatingWebhookConfiguration entry that
   targets a Service (clientConfig.service -- a URL-backed entry is out of
   this check's scope entirely, nothing here can verify an arbitrary URL)
   is only as good as that Service's backing Pods. Confirmed live: all 25
   webhook entries on this cluster are Service-backed, so this is not a
   theoretical path. A webhook whose Service does not exist, or whose
   Service exists but has zero ready Endpoints (checked via EndpointSlices,
   discovery.k8s.io/v1, label kubernetes.io/service-name -- an endpoint
   with no `ready` field at all is confirmed live to mean ready, not
   unknown, so an absent/null ready counts as ready here, matching upstream
   kube-proxy/EndpointSlice-consumer behavior) will silently reject or pass
   through every matching admission request depending on
   spec.webhooks[].failurePolicy (Fail is the default when unset, per
   admissionregistration.k8s.io/v1) -- worth flagging well before an
   operator notices requests failing admission for no visible reason.
   ExternalName Services are skipped: they are never backed by Pods or
   Endpoints by design, so "zero ready endpoints" would be a permanent false
   positive for the one Service type that legitimately has none.

   Both list dependencies (Services, EndpointSlices) are fetched once,
   cluster-wide, and reused across every webhook configuration and every
   entry in it, the same "list once, reuse" discipline as every other check
   module here. If either comes back None (a failed/denied call -- already
   recorded to client.unverifiable by client.py), nothing in this category
   can be verified, so the whole category is skipped rather than guessed at
   from half the data.
"""

import os
from datetime import datetime, timezone

from finalizers import EXPLICIT_KINDS, PROACTIVE_GROUPS

CATEGORY_STALE = "not-ready-long"
CATEGORY_WEBHOOK = "webhook-no-backend"

NODE_GROUP = ""
NODE_RESOURCE = "nodes"

WEBHOOK_GROUP = "admissionregistration.k8s.io"
WEBHOOK_API_VERSION = "admissionregistration.k8s.io/v1"
WEBHOOK_KINDS = [
    ("validatingwebhookconfigurations", "ValidatingWebhookConfiguration"),
    ("mutatingwebhookconfigurations", "MutatingWebhookConfiguration"),
]

SERVICE_NAME_LABEL = "kubernetes.io/service-name"

_TERMINAL_POD_PHASES = {"Succeeded", "Failed"}

_MESSAGE_TRUNCATE_LENGTH = 200


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


def _truncate(text):
    text = text or ""
    if len(text) <= _MESSAGE_TRUNCATE_LENGTH:
        return text
    return text[:_MESSAGE_TRUNCATE_LENGTH] + "..."


def _not_ready_after_hours():
    try:
        return float(os.environ.get("NOT_READY_AFTER_HOURS", "24"))
    except ValueError:
        return 24.0


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


def _condition_type_for(group, resource):
    if group == "apps" and resource == "deployments":
        return "Available"
    return "Ready"


def _find_condition(obj, condition_type):
    for cond in (obj.get("status", {}) or {}).get("conditions", []) or []:
        if cond.get("type") == condition_type:
            return cond
    return None


def _stale_problem(client, obj, group, resource, condition_type, now, threshold_seconds):
    metadata = obj.get("metadata", {}) or {}
    status = obj.get("status", {}) or {}

    if group == "" and resource == "pods" and status.get("phase") in _TERMINAL_POD_PHASES:
        return None

    cond = _find_condition(obj, condition_type)
    if cond is None:
        return None

    cond_status = cond.get("status")
    if cond_status == "True":
        return None

    since_raw = cond.get("lastTransitionTime")
    since_ts = _parse_ts(since_raw)
    if since_ts is None:
        return None

    age_seconds = (now - since_ts).total_seconds()
    if age_seconds < threshold_seconds:
        return None

    kind = _kind_for(client, group, resource, obj)
    api_version = _api_version_for(client, group, resource, obj)
    name = metadata.get("name", "<unknown>")
    namespace = metadata.get("namespace")
    reason = cond.get("reason") or "<no reason>"
    message = _truncate(cond.get("message"))
    severity = "critical" if (group, resource) == (NODE_GROUP, NODE_RESOURCE) else "warning"

    detail = "{}={} ({}: {}) since {} ({})".format(
        condition_type, cond_status, reason, message, since_raw, _format_duration(age_seconds)
    )

    return _base_problem(
        CATEGORY_STALE,
        severity,
        kind,
        api_version,
        namespace,
        name,
        detail,
        condition=condition_type,
        status=cond_status,
        reason=reason,
        since=since_raw,
        not_ready_for_seconds=int(age_seconds),
    )


def _scan_kind(client, group, resource, now, threshold_seconds, problems):
    items = client.list_resource(group, resource, namespace=None)
    if not items:
        return
    condition_type = _condition_type_for(group, resource)
    for obj in items:
        problem = _stale_problem(client, obj, group, resource, condition_type, now, threshold_seconds)
        if problem is not None:
            problems.append(problem)


def _scan_not_ready_long(client, now, problems):
    threshold_seconds = _not_ready_after_hours() * 3600

    for group, resource in EXPLICIT_KINDS:
        _scan_kind(client, group, resource, now, threshold_seconds, problems)

    for group in PROACTIVE_GROUPS:
        resources = client.group_resources(group)
        if not resources:
            continue
        for resource, _namespaced in resources:
            _scan_kind(client, group, resource, now, threshold_seconds, problems)

    _scan_kind(client, NODE_GROUP, NODE_RESOURCE, now, threshold_seconds, problems)


def _ready_endpoint_count(slices):
    count = 0
    for eps in slices:
        for endpoint in eps.get("endpoints") or []:
            conditions = endpoint.get("conditions") or {}
            if conditions.get("ready") is False:
                continue
            count += 1
    return count


def _endpointslices_by_service(endpointslices):
    index = {}
    for eps in endpointslices:
        labels = (eps.get("metadata", {}) or {}).get("labels") or {}
        service_name = labels.get(SERVICE_NAME_LABEL)
        if not service_name:
            continue
        namespace = (eps.get("metadata", {}) or {}).get("namespace")
        index.setdefault((namespace, service_name), []).append(eps)
    return index


def _webhook_problem(kind, config_name, webhook, services_by_key, eps_by_service):
    client_config = webhook.get("clientConfig") or {}
    service_ref = client_config.get("service")
    if not service_ref:
        return None

    svc_namespace = service_ref.get("namespace")
    svc_name = service_ref.get("name")
    webhook_name = webhook.get("name", "<unknown>")
    failure_policy = webhook.get("failurePolicy") or "Fail"

    svc = services_by_key.get((svc_namespace, svc_name))
    if svc is None:
        failure = "its Service {}/{} was not found".format(svc_namespace, svc_name)
    else:
        if ((svc.get("spec") or {}).get("type")) == "ExternalName":
            return None
        ready = _ready_endpoint_count(eps_by_service.get((svc_namespace, svc_name), []))
        if ready > 0:
            return None
        failure = "its Service {}/{} has zero ready endpoints".format(svc_namespace, svc_name)

    severity = "warning" if failure_policy == "Ignore" else "critical"
    effect = (
        "admission requests are allowed through unvalidated"
        if severity == "warning"
        else "admission requests are rejected"
    )

    return _base_problem(
        CATEGORY_WEBHOOK,
        severity,
        kind,
        WEBHOOK_API_VERSION,
        None,
        config_name,
        "webhook {} {}; failurePolicy={} ({})".format(
            webhook_name, failure, failure_policy, effect
        ),
        webhook=webhook_name,
        service="{}/{}".format(svc_namespace, svc_name),
        failure_policy=failure_policy,
    )


def _scan_webhooks(client, problems):
    services = client.list_resource("", "services")
    endpointslices = client.list_resource("discovery.k8s.io", "endpointslices")
    if services is None or endpointslices is None:
        return

    services_by_key = {}
    for svc in services:
        metadata = svc.get("metadata", {}) or {}
        services_by_key[(metadata.get("namespace"), metadata.get("name"))] = svc

    eps_by_service = _endpointslices_by_service(endpointslices)

    for resource, kind in WEBHOOK_KINDS:
        configs = client.list_resource(WEBHOOK_GROUP, resource)
        if not configs:
            continue
        for config in configs:
            config_name = config.get("metadata", {}).get("name", "<unknown>")
            for webhook in config.get("webhooks") or []:
                problem = _webhook_problem(
                    kind, config_name, webhook, services_by_key, eps_by_service
                )
                if problem is not None:
                    problems.append(problem)


def check(client, now):
    problems = []
    _scan_not_ready_long(client, now, problems)
    _scan_webhooks(client, problems)
    return problems
