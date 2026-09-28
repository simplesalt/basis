#!/usr/bin/env python3
"""Local test for platform/cluster-health's stale.check(), no cluster access.

Same approach as the other test-cluster-health-*.py scripts (see
test-cluster-health.py's docstring): stale.check() runs against a
FakeClient loaded with fixture Kubernetes objects instead of the real
client.py. FakeClient implements the surface stale.py actually calls
(list_resource, group_resources, .unverifiable) -- it also needs
group_resources because stale.py walks finalizers.EXPLICIT_KINDS and
finalizers.PROACTIVE_GROUPS the same way finalizers.check() does.

Three scenarios:

1. run_not_ready_long() -- the not-ready-long category: the two live cases
   from the parent Effort's request (ClusterIssuer simplesalt Ready=False
   39d, Record info-simplesalt-company Ready=False 38d, both reached only
   through a PROACTIVE_GROUPS group's group_resources() walk); an object
   not Ready for only 2h (under the default 24h threshold, not flagged); a
   Succeeded and a Failed Job pod (skipped by phase, even though Ready=False
   for a long time); a healthy/Ready object (not flagged); a Running pod
   not Ready for 2 days (flagged); a Deployment with Available=False for
   2 days (flagged via the Available condition, not Ready); a Node with
   Ready=Unknown for 2 days (flagged, critical -- the only Node-severity
   case); and a condition with no parseable lastTransitionTime (skipped).
2. run_webhooks() -- the webhook-no-backend category: a webhook whose
   Service is missing (failurePolicy unset -> Fail -> critical); one whose
   Service exists but has zero ready endpoints (failurePolicy Ignore ->
   warning); an endpoint with no "ready" field at all, which must count as
   ready; a healthy webhook (not flagged); a URL-backed webhook (not
   flagged, skipped entirely); and an ExternalName Service backing a
   webhook with zero Endpoints (not flagged -- Services of that type never
   have any, by design).
3. run_none_lists() -- a denied list (services, for the webhook category;
   a PROACTIVE_GROUPS resource, for not-ready-long) must be skipped
   quietly and produce zero problems from the dependent category, not a
   crash or a guess.

    scripts/test-cluster-health-stale.py
"""

import os
import sys
import traceback
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "platform", "cluster-health"))

import stale

NOW = datetime.now(timezone.utc).replace(microsecond=0)


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def hours_ago(hours):
    return iso(NOW - timedelta(hours=hours))


def days_ago(days):
    return iso(NOW - timedelta(days=days))


class FakeClient:
    """A fixture-backed stand-in for client.Client, covering only the
    surface stale.py calls: list_resource, group_resources, .unverifiable,
    plus kind_for/api_version_for (client.py's discovery-backed fallback
    for an item that carries no kind/apiVersion of its own -- see its
    module docstring). set_kind registers what a real Client's discovery
    would have answered for a (group, resource) pair; a pair nothing
    registers falls back to None the same way client.Client's real
    kind_for/api_version_for do for an unresolvable group/resource.

    deny_resource simulates an RBAC 403 (or any other failed call) the way
    client.py's get_safe records one: append to self.unverifiable and
    return None instead of raising.
    """

    def __init__(self):
        self.unverifiable = []
        self._resources = {}
        self._group_resources = {}
        self._deny_resources = {}
        self._kinds = {}

    def set_resource(self, group, resource, namespace, items):
        self._resources[(group, resource, namespace)] = items

    def deny_resource(self, group, resource, namespace, detail="403 Forbidden"):
        self._deny_resources[(group, resource, namespace)] = detail

    def list_resource(self, group, resource, namespace=None):
        key = (group, resource, namespace)
        if key in self._deny_resources:
            scope = "namespace {}".format(namespace) if namespace else "cluster-wide"
            attempted = "list {}{} ({})".format(
                resource, "." + group if group else "", scope
            )
            self.unverifiable.append(
                {"attempted": attempted, "detail": self._deny_resources[key]}
            )
            return None
        return self._resources.get(key, [])

    def set_group_resources(self, group, resources):
        self._group_resources[group] = resources

    def group_resources(self, group):
        return self._group_resources.get(group, [])

    def set_kind(self, group, resource, kind, api_version):
        self._kinds[(group, resource)] = (kind, api_version)

    def kind_for(self, group, resource):
        entry = self._kinds.get((group, resource))
        return entry[0] if entry else None

    def api_version_for(self, group, resource):
        entry = self._kinds.get((group, resource))
        return entry[1] if entry else None




def _condition(ctype, status, reason="Reason", message="detail", since=None):
    cond = {"type": ctype, "status": status, "reason": reason, "message": message}
    if since is not None:
        cond["lastTransitionTime"] = since
    return cond


def _object(kind, api_version, name, namespace=None, conditions=None, phase=None):
    metadata = {"name": name}
    if namespace:
        metadata["namespace"] = namespace
    status = {}
    if conditions is not None:
        status["conditions"] = conditions
    if phase is not None:
        status["phase"] = phase
    return {
        "apiVersion": api_version,
        "kind": kind,
        "metadata": metadata,
        "status": status,
    }


def _object_no_gvk(name, namespace=None, conditions=None, phase=None):
    """Same shape as _object, but with no "kind"/"apiVersion" at all -- the
    real Kubernetes API's own shape for every item of a builtin Kind's list
    response (Node, Pod, Deployment, ...; a custom resource's items do carry
    both -- see client.py's module docstring). Exercises stale.py's
    client.kind_for/api_version_for fallback instead of the item's own
    fields."""
    metadata = {"name": name}
    if namespace:
        metadata["namespace"] = namespace
    status = {}
    if conditions is not None:
        status["conditions"] = conditions
    if phase is not None:
        status["phase"] = phase
    return {"metadata": metadata, "status": status}


def _service(name, namespace, svc_type=None):
    spec = {}
    if svc_type is not None:
        spec["type"] = svc_type
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": name, "namespace": namespace},
        "spec": spec,
    }


def _endpoint(ready=None):
    conditions = {}
    if ready is not None:
        conditions["ready"] = ready
    return {"conditions": conditions, "addresses": ["10.0.0.1"]}


def _endpointslice(name, namespace, service_name, endpoints):
    return {
        "apiVersion": "discovery.k8s.io/v1",
        "kind": "EndpointSlice",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {"kubernetes.io/service-name": service_name},
        },
        "endpoints": endpoints,
    }


def _webhook_entry(name, namespace=None, service_name=None, failure_policy=None, url=None):
    webhook = {"name": name, "failurePolicy": failure_policy}
    client_config = {}
    if url is not None:
        client_config["url"] = url
    elif service_name is not None:
        client_config["service"] = {"namespace": namespace, "name": service_name, "port": 443}
    webhook["clientConfig"] = client_config
    return webhook


def _webhook_config(name, webhooks):
    return {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingWebhookConfiguration",
        "metadata": {"name": name},
        "webhooks": webhooks,
    }


FAILURES = []


def check(label, condition, detail=""):
    status = "ok" if condition else "FAIL"
    print("  [{}] {}{}".format(status, label, "" if condition else " -- " + detail))
    if not condition:
        FAILURES.append(label)


def find_problem(problems, name, category=None):
    for p in problems:
        if p.get("name") == name and (category is None or p.get("category") == category):
            return p
    return None


def count_category(problems, category):
    return sum(1 for p in problems if p.get("category") == category)




def run_not_ready_long():
    print("-- scenario: not-ready-long --")
    client = FakeClient()

    cluster_issuer = _object(
        "ClusterIssuer",
        "cert-manager.io/v1",
        "simplesalt",
        conditions=[_condition("Ready", "False", "InvalidSolver", "no solver configured", days_ago(39))],
    )
    client.set_group_resources("cert-manager.io", [("clusterissuers", False)])
    client.set_resource("cert-manager.io", "clusterissuers", None, [cluster_issuer])

    record = _object(
        "Record",
        "dns.upjet-cloudflare.upbound.io/v1alpha1",
        "info-simplesalt-company",
        conditions=[_condition("Ready", "False", "Creating", "still creating", days_ago(38))],
    )
    client.set_group_resources("dns.upjet-cloudflare.upbound.io", [("records", False)])
    client.set_resource("dns.upjet-cloudflare.upbound.io", "records", None, [record])

    ci_recent = _object(
        "ClusterIssuer",
        "cert-manager.io/v1",
        "ci-recent-not-ready",
        conditions=[_condition("Ready", "False", "InvalidSolver", "...", hours_ago(2))],
    )
    client.set_resource("cert-manager.io", "clusterissuers", None, [cluster_issuer, ci_recent])

    client.set_group_resources("kustomize.toolkit.fluxcd.io", [])

    pod_succeeded = _object(
        "Pod", "v1", "job-completed", namespace="batch",
        conditions=[_condition("Ready", "False", "PodCompleted", "...", days_ago(5))],
        phase="Succeeded",
    )
    pod_failed = _object(
        "Pod", "v1", "job-failed", namespace="batch",
        conditions=[_condition("Ready", "False", "PodFailed", "...", days_ago(5))],
        phase="Failed",
    )
    pod_healthy = _object(
        "Pod", "v1", "app-healthy", namespace="apps",
        conditions=[_condition("Ready", "True", "PodReady", "...", days_ago(10))],
        phase="Running",
    )
    pod_stuck = _object(
        "Pod", "v1", "app-not-ready", namespace="apps",
        conditions=[_condition("Ready", "False", "ContainersNotReady", "container crashlooping", days_ago(2))],
        phase="Running",
    )
    pod_bad_ts = _object(
        "Pod", "v1", "app-bad-timestamp", namespace="apps",
        conditions=[_condition("Ready", "False", "Unknown", "...", since="not-a-timestamp")],
        phase="Running",
    )
    client.set_resource(
        "", "pods", None, [pod_succeeded, pod_failed, pod_healthy, pod_stuck, pod_bad_ts]
    )

    client.set_kind("apps", "deployments", "Deployment", "apps/v1")
    client.set_kind("", "nodes", "Node", "v1")

    deployment_stuck = _object(
        "Deployment", "apps/v1", "web", namespace="apps",
        conditions=[_condition("Available", "False", "MinimumReplicasUnavailable", "0/3 ready", days_ago(2))],
    )
    deployment_no_gvk = _object_no_gvk(
        "web-no-gvk", namespace="apps",
        conditions=[_condition("Available", "False", "MinimumReplicasUnavailable", "0/3 ready", days_ago(2))],
    )
    client.set_resource("apps", "deployments", None, [deployment_stuck, deployment_no_gvk])

    node_unknown = _object(
        "Node", "v1", "k-0ad0ff18",
        conditions=[_condition("Ready", "Unknown", "NodeStatusUnknown", "kubelet stopped posting", days_ago(2))],
    )
    node_no_gvk = _object_no_gvk(
        "k-no-gvk",
        conditions=[_condition("Ready", "False", "NodeNotReady", "kubelet stopped posting", days_ago(2))],
    )
    client.set_resource("", "nodes", None, [node_unknown, node_no_gvk])

    problems = stale.check(client, NOW)
    stale_problems = [p for p in problems if p["category"] == stale.CATEGORY_STALE]

    print("not-ready-long problems found: {}".format(len(stale_problems)))
    for p in stale_problems:
        print("  - [{}] {} {}/{}  {}".format(p["severity"], p["kind"], p.get("namespace"), p["name"], p["detail"]))

    check(
        "ClusterIssuer Ready=False for 39d (reached via PROACTIVE_GROUPS "
        "group_resources) is flagged not-ready-long, warning",
        (lambda p: p is not None and p["severity"] == "warning" and p["condition"] == "Ready")(
            find_problem(stale_problems, "simplesalt")
        ),
        "found={}".format(find_problem(stale_problems, "simplesalt")),
    )

    check(
        "Record Ready=False for 38d (reached via PROACTIVE_GROUPS "
        "group_resources) is flagged not-ready-long",
        find_problem(stale_problems, "info-simplesalt-company") is not None,
        "found={}".format(find_problem(stale_problems, "info-simplesalt-company")),
    )

    check(
        "an object Ready=False for only 2h (under the default 24h threshold) "
        "is not flagged",
        find_problem(stale_problems, "ci-recent-not-ready") is None,
        "found={}".format(find_problem(stale_problems, "ci-recent-not-ready")),
    )

    check(
        "a Succeeded Job pod is skipped by phase, not flagged",
        find_problem(stale_problems, "job-completed") is None,
        "found={}".format(find_problem(stale_problems, "job-completed")),
    )
    check(
        "a Failed pod is skipped by phase, not flagged",
        find_problem(stale_problems, "job-failed") is None,
        "found={}".format(find_problem(stale_problems, "job-failed")),
    )
    check(
        "a healthy Ready=True pod is not flagged",
        find_problem(stale_problems, "app-healthy") is None,
        "found={}".format(find_problem(stale_problems, "app-healthy")),
    )
    check(
        "a Running pod Ready=False for 2 days is flagged, warning",
        (lambda p: p is not None and p["severity"] == "warning")(find_problem(stale_problems, "app-not-ready")),
        "found={}".format(find_problem(stale_problems, "app-not-ready")),
    )
    check(
        "a condition with no parseable lastTransitionTime is skipped, not flagged",
        find_problem(stale_problems, "app-bad-timestamp") is None,
        "found={}".format(find_problem(stale_problems, "app-bad-timestamp")),
    )

    deployment_problem = find_problem(stale_problems, "web")
    check(
        "a Deployment with Available=False for 2 days is flagged via the "
        "Available condition (not Ready), warning",
        deployment_problem is not None
        and deployment_problem["condition"] == "Available"
        and deployment_problem["severity"] == "warning",
        "found={}".format(deployment_problem),
    )

    node_problem = find_problem(stale_problems, "k-0ad0ff18")
    check(
        "a Node with Ready=Unknown for 2 days is flagged, severity critical "
        "(the only Node case)",
        node_problem is not None
        and node_problem["kind"] == "Node"
        and node_problem["severity"] == "critical"
        and node_problem["status"] == "Unknown",
        "found={}".format(node_problem),
    )

    deployment_no_gvk_problem = find_problem(stale_problems, "web-no-gvk")
    check(
        "a Deployment item with no kind/apiVersion of its own is still "
        "labeled Deployment, apps/v1 via client.kind_for/api_version_for, "
        "severity warning",
        deployment_no_gvk_problem is not None
        and deployment_no_gvk_problem["kind"] == "Deployment"
        and deployment_no_gvk_problem["apiVersion"] == "apps/v1"
        and deployment_no_gvk_problem["severity"] == "warning",
        "found={}".format(deployment_no_gvk_problem),
    )

    node_no_gvk_problem = find_problem(stale_problems, "k-no-gvk")
    check(
        "a Node not Ready for 2 days with no kind/apiVersion of its own is "
        "still labeled Node, v1, critical via client.kind_for/"
        "api_version_for, keyed on (group, resource) rather than a kind "
        "string it never carries -- the labeling defect this fix addresses",
        node_no_gvk_problem is not None
        and node_no_gvk_problem["kind"] == "Node"
        and node_no_gvk_problem["apiVersion"] == "v1"
        and node_no_gvk_problem["severity"] == "critical",
        "found={}".format(node_no_gvk_problem),
    )

    print()




def run_webhooks():
    print("-- scenario: webhook-no-backend --")
    client = FakeClient()

    services = [
        _service("healthy-svc", "webhook-ns"),
        _service("zero-ready-svc", "webhook-ns"),
        _service("unset-ready-svc", "webhook-ns"),
        _service("externalname-svc", "webhook-ns", svc_type="ExternalName"),
    ]
    client.set_resource("", "services", None, services)

    endpointslices = [
        _endpointslice("healthy-svc-abcde", "webhook-ns", "healthy-svc", [_endpoint(ready=True)]),
        _endpointslice("zero-ready-svc-abcde", "webhook-ns", "zero-ready-svc", [_endpoint(ready=False)]),
        _endpointslice("unset-ready-svc-abcde", "webhook-ns", "unset-ready-svc", [_endpoint(ready=None)]),
    ]
    client.set_resource("discovery.k8s.io", "endpointslices", None, endpointslices)

    validating = _webhook_config(
        "vwc-checks",
        [
            _webhook_entry("missing.example.com", "webhook-ns", "missing-svc", failure_policy=None),
            _webhook_entry("zero-ready.example.com", "webhook-ns", "zero-ready-svc", failure_policy="Ignore"),
            _webhook_entry("unset-ready.example.com", "webhook-ns", "unset-ready-svc", failure_policy="Fail"),
            _webhook_entry("healthy.example.com", "webhook-ns", "healthy-svc", failure_policy="Fail"),
            _webhook_entry("url-backed.example.com", url="https://external.example.com/validate"),
            _webhook_entry(
                "externalname.example.com", "webhook-ns", "externalname-svc", failure_policy="Fail"
            ),
        ],
    )
    client.set_resource(
        "admissionregistration.k8s.io", "validatingwebhookconfigurations", None, [validating]
    )
    client.set_resource("admissionregistration.k8s.io", "mutatingwebhookconfigurations", None, [])

    problems = stale.check(client, NOW)
    webhook_problems = [p for p in problems if p["category"] == stale.CATEGORY_WEBHOOK]

    print("webhook-no-backend problems found: {}".format(len(webhook_problems)))
    for p in webhook_problems:
        print("  - [{}] {} webhook={} service={}".format(p["severity"], p["name"], p["webhook"], p["service"]))

    check(
        "exactly 2 webhook problems reported",
        len(webhook_problems) == 2,
        "found {}".format(len(webhook_problems)),
    )

    missing = find_problem(webhook_problems, "vwc-checks")
    missing_entries = [p for p in webhook_problems if p["webhook"] == "missing.example.com"]
    check(
        "a webhook whose Service is missing, failurePolicy unset (defaults "
        "to Fail), is flagged critical",
        len(missing_entries) == 1
        and missing_entries[0]["severity"] == "critical"
        and missing_entries[0]["failure_policy"] == "Fail"
        and missing_entries[0]["service"] == "webhook-ns/missing-svc",
        "found={}".format(missing_entries),
    )

    zero_ready_entries = [p for p in webhook_problems if p["webhook"] == "zero-ready.example.com"]
    check(
        "a webhook whose Service has zero ready endpoints, failurePolicy "
        "Ignore, is flagged warning",
        len(zero_ready_entries) == 1 and zero_ready_entries[0]["severity"] == "warning",
        "found={}".format(zero_ready_entries),
    )

    check(
        "a webhook whose Service's only endpoint has no ready field at all "
        "is not flagged -- absent ready counts as ready",
        not any(p["webhook"] == "unset-ready.example.com" for p in webhook_problems),
        "problems={}".format(webhook_problems),
    )
    check(
        "a healthy webhook (Service exists, has a ready endpoint) is not flagged",
        not any(p["webhook"] == "healthy.example.com" for p in webhook_problems),
        "problems={}".format(webhook_problems),
    )
    check(
        "a URL-backed webhook entry is skipped entirely, not flagged",
        not any(p["webhook"] == "url-backed.example.com" for p in webhook_problems),
        "problems={}".format(webhook_problems),
    )
    check(
        "an ExternalName Service backing a webhook is never flagged even "
        "with zero Endpoints -- it has none by design",
        not any(p["webhook"] == "externalname.example.com" for p in webhook_problems),
        "problems={}".format(webhook_problems),
    )

    print()




def run_none_lists():
    print("-- scenario: a None list produces no problems --")

    client_a = FakeClient()
    client_a.set_group_resources("cert-manager.io", [("clusterissuers", False)])
    client_a.deny_resource("cert-manager.io", "clusterissuers", None, detail="403 Forbidden")

    problems_a = stale.check(client_a, NOW)
    check(
        "a denied PROACTIVE_GROUPS resource list produces zero "
        "not-ready-long problems and does not crash the scan",
        [p for p in problems_a if p["category"] == stale.CATEGORY_STALE] == [],
        "problems={}".format(problems_a),
    )
    check(
        "the denial is recorded to unverifiable",
        any("clusterissuers" in e["attempted"] for e in client_a.unverifiable),
        "unverifiable={}".format(client_a.unverifiable),
    )

    client_b = FakeClient()
    client_b.deny_resource("", "services", None, detail="403 Forbidden")
    client_b.set_resource("discovery.k8s.io", "endpointslices", None, [])
    client_b.set_resource(
        "admissionregistration.k8s.io",
        "validatingwebhookconfigurations",
        None,
        [_webhook_config("vwc-unverifiable", [_webhook_entry("w.example.com", "ns", "svc")])],
    )
    client_b.set_resource("admissionregistration.k8s.io", "mutatingwebhookconfigurations", None, [])

    problems_b = stale.check(client_b, NOW)
    check(
        "a denied services list produces zero webhook-no-backend problems, "
        "even with a webhook config present",
        [p for p in problems_b if p["category"] == stale.CATEGORY_WEBHOOK] == [],
        "problems={}".format(problems_b),
    )

    print()


def run():
    run_not_ready_long()
    run_webhooks()
    run_none_lists()

    if FAILURES:
        print("FAILED: {}".format(", ".join(FAILURES)))
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(run())
    except Exception:
        traceback.print_exc()
        sys.exit(1)
