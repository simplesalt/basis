#!/usr/bin/env python3
"""Local test for platform/cluster-health's checks, no cluster access.

Runs finalizers.check() against a FakeClient loaded with fixture Kubernetes
objects (plain JSON-shaped dicts -- the same shapes a real `GET .../items[]`
response carries) instead of the real client.py, which needs an in-cluster
ServiceAccount token and API server. FakeClient implements the same surface
finalizers.py actually calls (list_resource, group_resources,
list_deployments, .unverifiable) and nothing more, so a real Client swapped
in for it is exercised the same way.

    scripts/test-cluster-health.py
"""

import json
import os
import sys
import traceback
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "platform", "cluster-health"))

import finalizers  # noqa: E402

NOW = datetime.now(timezone.utc).replace(microsecond=0)


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def ago(minutes):
    return iso(NOW - timedelta(minutes=minutes))


def _selector_key(match_labels, label_selector):
    if label_selector:
        return ("raw", label_selector)
    return ("labels", tuple(sorted((match_labels or {}).items())))


class FakeClient:
    """A fixture-backed stand-in for client.Client.

    Every fixture is loaded through set_resource/set_group_resources/
    set_deployments; deny_resource/deny_deployments simulate an RBAC 403 (or
    any other failed call) the way client.py's get_safe records one: append
    to self.unverifiable and return None instead of raising.
    """

    def __init__(self):
        self.unverifiable = []
        self._resources = {}
        self._group_resources = {}
        self._deployments = {}
        self._deny_resources = {}
        self._deny_deployments = {}

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

    def set_deployments(self, namespace, items, match_labels=None, label_selector=None):
        key = (namespace, _selector_key(match_labels, label_selector))
        self._deployments[key] = items

    def deny_deployments(self, namespace, match_labels=None, label_selector=None, detail="403 Forbidden"):
        key = (namespace, _selector_key(match_labels, label_selector))
        self._deny_deployments[key] = detail

    def list_deployments(self, namespace, match_labels=None, label_selector=None):
        key = (namespace, _selector_key(match_labels, label_selector))
        if key in self._deny_deployments:
            self.unverifiable.append(
                {
                    "attempted": "list deployments in {} matching {!r}".format(
                        namespace, match_labels or label_selector
                    ),
                    "detail": self._deny_deployments[key],
                }
            )
            return None
        return self._deployments.get(key, [])


def _namespace(name, deletion_minutes_ago=None, spec_finalizers=None, conditions=None, phase="Active"):
    ns = {
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {"name": name},
        "spec": {},
        "status": {"phase": phase, "conditions": conditions or []},
    }
    if deletion_minutes_ago is not None:
        ns["metadata"]["deletionTimestamp"] = ago(deletion_minutes_ago)
        ns["status"]["phase"] = "Terminating"
    if spec_finalizers is not None:
        ns["spec"]["finalizers"] = spec_finalizers
    return ns


def _content_remaining_condition(gvr_tokens):
    items = ["{} has 1 resource instances".format(t) for t in gvr_tokens]
    return {
        "type": "NamespaceContentRemaining",
        "status": "True",
        "reason": "SomeResourcesRemain",
        "message": "Some resources are remaining: " + ", ".join(items),
    }


def _managed_resource(name, namespace, group, kind, minutes_ago, finalizers_list):
    return {
        "apiVersion": "{}/v1beta1".format(group),
        "kind": kind,
        "metadata": {
            "name": name,
            "namespace": namespace,
            "deletionTimestamp": ago(minutes_ago),
            "finalizers": finalizers_list,
        },
    }


def _deployment(name, namespace, replicas=1, ready=1, labels=None):
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": name, "namespace": namespace, "labels": labels or {}},
        "spec": {"replicas": replicas},
        "status": {"readyReplicas": ready},
    }


FAILURES = []


def check(label, condition, detail=""):
    status = "ok" if condition else "FAIL"
    print("  [{}] {}{}".format(status, label, "" if condition else " -- " + detail))
    if not condition:
        FAILURES.append(label)


def find_problem(problems, name):
    for p in problems:
        if p.get("name") == name:
            return p
    return None


def run():
    client = FakeClient()

    # --- fixtures -----------------------------------------------------
    ns_missing_provider = _namespace(
        "crossplane-orphan-ns",
        deletion_minutes_ago=40,
        spec_finalizers=["kubernetes"],
        conditions=[
            _content_remaining_condition(["instances.cloudplatform.gcp.upbound.io"])
        ],
    )
    ns_young = _namespace(
        "young-delete-ns",
        deletion_minutes_ago=5,
        spec_finalizers=["kubernetes"],
    )
    ns_active = _namespace("cluster-main-observability")

    client.set_resource("", "namespaces", None, [ns_missing_provider, ns_young, ns_active])

    stuck_instance = _managed_resource(
        "stuck-instance",
        "crossplane-orphan-ns",
        "cloudplatform.gcp.upbound.io",
        "Instance",
        minutes_ago=40,
        finalizers_list=["finalizer.managedresource.crossplane.io"],
    )
    client.set_resource(
        "cloudplatform.gcp.upbound.io", "instances", "crossplane-orphan-ns", [stuck_instance]
    )
    # the provider Deployment is missing entirely -> controller "missing"
    client.set_deployments(
        "crossplane-system",
        [],
        match_labels={"pkg.crossplane.io/provider": "provider-gcp-cloudplatform"},
    )

    # cluster-scoped kinds: PVs denied (RBAC 403), CRDs verified-empty
    client.deny_resource("", "persistentvolumes", None, detail="403 Forbidden: persistentvolumes is forbidden")
    client.set_resource("apiextensions.k8s.io", "customresourcedefinitions", None, [])

    # proactively-scanned groups: a running Flux controller and a not-ready one
    client.set_group_resources("kustomize.toolkit.fluxcd.io", [("kustomizations", True)])
    client.set_group_resources("helm.toolkit.fluxcd.io", [("helmreleases", True)])
    client.set_group_resources("source.toolkit.fluxcd.io", [])
    client.set_group_resources("pkg.crossplane.io", [])
    client.set_group_resources("apiextensions.crossplane.io", [])

    stuck_kustomization = _managed_resource(
        "stuck-ks", "flux-system", "kustomize.toolkit.fluxcd.io", "Kustomization",
        minutes_ago=20, finalizers_list=["finalizers.fluxcd.io"],
    )
    client.set_resource("kustomize.toolkit.fluxcd.io", "kustomizations", None, [stuck_kustomization])
    client.set_deployments(
        "flux-system", [_deployment("kustomize-controller", "flux-system", replicas=1, ready=1)],
        match_labels={"app": "kustomize-controller"},
    )

    stuck_helmrelease = _managed_resource(
        "stuck-hr", "flux-system", "helm.toolkit.fluxcd.io", "HelmRelease",
        minutes_ago=25, finalizers_list=["finalizers.fluxcd.io"],
    )
    client.set_resource("helm.toolkit.fluxcd.io", "helmreleases", None, [stuck_helmrelease])
    client.set_deployments(
        "flux-system", [_deployment("helm-controller", "flux-system", replicas=1, ready=0)],
        match_labels={"app": "helm-controller"},
    )

    # unknown group: no controller-map entry
    unknown_obj = _managed_resource(
        "stuck-unknown", "cluster-main-observability", "example.acme.io", "Widget",
        minutes_ago=30, finalizers_list=["example.acme.io/cleanup"],
    )
    client.set_resource("apiextensions.k8s.io", "customresourcedefinitions", None, [])
    # (route it in as a condition-named target on a namespace so it's scanned)
    ns_unknown = _namespace(
        "unknown-ns", deletion_minutes_ago=30, spec_finalizers=["kubernetes"],
        conditions=[_content_remaining_condition(["widgets.example.acme.io"])],
    )
    client.set_resource("", "namespaces", None, [ns_missing_provider, ns_young, ns_active, ns_unknown])
    client.set_resource("example.acme.io", "widgets", "unknown-ns", [unknown_obj])

    # --- run ------------------------------------------------------------
    problems = finalizers.check(client, NOW)

    # --- assertions -------------------------------------------------
    print("problems found: {}".format(len(problems)))
    for p in problems:
        print("  - {} {}/{}  controller={}  severity={}".format(
            p["kind"], p.get("namespace"), p["name"], p["controller"], p["severity"]
        ))

    missing = find_problem(problems, "stuck-instance")
    check(
        "stale crossplane finalizer with missing provider Deployment is flagged, controller=missing",
        missing is not None and missing["controller"] == "missing" and missing["category"] == "orphaned-finalizer",
        "found={}".format(missing),
    )

    young = find_problem(problems, "young-delete-ns")
    check(
        "a 5-minute-old delete is not flagged",
        young is None,
        "found={}".format(young),
    )

    check(
        "RBAC 403 on persistentvolumes lands in unverifiable with what was attempted",
        any(
            "persistentvolumes" in entry["attempted"] and "403" in entry["detail"]
            for entry in client.unverifiable
        ),
        "unverifiable={}".format(client.unverifiable),
    )

    old_missing_ns = find_problem(problems, "crossplane-orphan-ns")
    check(
        "the terminating namespace's own builtin finalizer is flagged separately, controller=builtin",
        old_missing_ns is not None and old_missing_ns["controller"] == "builtin",
        "found={}".format(old_missing_ns),
    )

    running = find_problem(problems, "stuck-ks")
    check(
        "a stuck object whose controller Deployment is ready reports controller=running",
        running is not None and running["controller"] == "running",
        "found={}".format(running),
    )

    not_ready = find_problem(problems, "stuck-hr")
    check(
        "a stuck object whose controller Deployment has 0 ready replicas reports controller=not-ready",
        not_ready is not None and not_ready["controller"] == "not-ready",
        "found={}".format(not_ready),
    )

    unknown = find_problem(problems, "stuck-unknown")
    check(
        "a stuck object in a group with no controller-map entry reports controller=unknown",
        unknown is not None and unknown["controller"] == "unknown",
        "found={}".format(unknown),
    )

    print()
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
