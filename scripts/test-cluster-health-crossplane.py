#!/usr/bin/env python3
"""Local test for platform/cluster-health's crossplane.check(), no cluster access.

Same approach as test-cluster-health.py (see its docstring): a FakeClient
loaded with fixture Kubernetes objects shaped like the real ones, exercising
only the surface crossplane.py actually calls (list_resource,
list_deployments, .unverifiable).

    scripts/test-cluster-health-crossplane.py
"""

import os
import sys
import traceback
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "platform", "cluster-health"))

import crossplane  # noqa: E402

NOW = datetime.now(timezone.utc).replace(microsecond=0)


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def ago(minutes):
    return iso(NOW - timedelta(minutes=minutes))


class FakeClient:
    """A fixture-backed stand-in for client.Client -- see
    test-cluster-health.py's FakeClient for the pattern this mirrors. Only
    implements what crossplane.py actually calls: list_resource,
    list_deployments, .unverifiable.
    """

    def __init__(self):
        self.unverifiable = []
        self._resources = {}
        self._deny_resources = {}
        self._deployments = {}

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

    def set_deployments(self, namespace, items):
        self._deployments[namespace] = items

    def list_deployments(self, namespace, match_labels=None, label_selector=None):
        # crossplane.py always lists a whole namespace unfiltered (see its
        # module docstring on why a server-side label selector can't be used
        # here), so this fake only needs to support that one call shape.
        return self._deployments.get(namespace, [])


# --- fixture builders ----------------------------------------------------


def _crd(group, plural, kind, scope, categories=("crossplane", "managed")):
    return {
        "apiVersion": "apiextensions.k8s.io/v1",
        "kind": "CustomResourceDefinition",
        "metadata": {"name": "{}.{}".format(plural, group)},
        "spec": {
            "group": group,
            "names": {
                "categories": list(categories),
                "kind": kind,
                "plural": plural,
                "singular": kind.lower(),
            },
            "scope": scope,
        },
    }


def _condition(ctype, status, reason="Reason", message="detail"):
    return {"type": ctype, "status": status, "reason": reason, "message": message}


def _managed_object(name, group, kind=None, namespace=None, conditions=None,
                     annotations=None, api_version=True):
    metadata = {"name": name}
    if namespace:
        metadata["namespace"] = namespace
    if annotations:
        metadata["annotations"] = annotations
    obj = {"metadata": metadata, "status": {"conditions": conditions or []}}
    if api_version:
        obj["apiVersion"] = "{}/v1alpha1".format(group)
    if kind:
        obj["kind"] = kind
    return obj


def _provider(name, installed="True", healthy="True"):
    return {
        "apiVersion": "pkg.crossplane.io/v1",
        "kind": "Provider",
        "metadata": {"name": name},
        "status": {
            "conditions": [
                _condition("Installed", installed, "ActivePackageRevision"),
                _condition("Healthy", healthy, "HealthyPackageRevision"),
            ]
        },
    }


def _provider_revision(name, revision_healthy="True", runtime_healthy="True", runtime_active="True"):
    return {
        "apiVersion": "pkg.crossplane.io/v1",
        "kind": "ProviderRevision",
        "metadata": {"name": name},
        "status": {
            "conditions": [
                _condition("RevisionHealthy", revision_healthy, "HealthyPackageRevision"),
                _condition("RuntimeHealthy", runtime_healthy, "HealthyPackageRevision"),
                _condition("RuntimeActive", runtime_active, "ActiveRuntime"),
            ]
        },
    }


def _provider_deployment(name, provider_name, replicas=1, ready=1):
    return {
        "metadata": {"name": name, "namespace": "crossplane-system"},
        "spec": {
            "replicas": replicas,
            "selector": {"matchLabels": {"pkg.crossplane.io/provider": provider_name}},
        },
        "status": {"readyReplicas": ready},
    }


FAILURES = []


def check(label, condition, detail=""):
    status = "ok" if condition else "FAIL"
    print("  [{}] {}{}".format(status, label, "" if condition else " -- " + detail))
    if not condition:
        FAILURES.append(label)


def find_problems(problems, name):
    return [p for p in problems if p.get("name") == name]


def find_problem(problems, name, category):
    for p in find_problems(problems, name):
        if p.get("category") == category:
            return p
    return None


# --- unhealthy fixture set: every flagged condition, once each -----------


def run_unhealthy():
    client = FakeClient()

    crd_cluster = _crd("r2.upjet-cloudflare.upbound.io", "buckets", "Bucket", "Cluster")
    crd_namespaced = _crd("cloudplatform.gcp.m.upbound.io", "projects", "Project", "Namespaced")
    crd_denied = _crd("dns.upjet-cloudflare.m.upbound.io", "records", "Record", "Namespaced")
    crd_not_managed = _crd(
        "apiextensions.crossplane.io", "compositeresourcedefinitions",
        "CompositeResourceDefinition", "Cluster", categories=("crossplane",),
    )
    client.set_resource(
        "apiextensions.k8s.io", "customresourcedefinitions", None,
        [crd_cluster, crd_namespaced, crd_denied, crd_not_managed],
    )
    client.deny_resource(
        "dns.upjet-cloudflare.m.upbound.io", "records", None,
        detail="403 Forbidden: records is forbidden",
    )

    buckets = [
        _managed_object(
            "bucket-not-synced", "r2.upjet-cloudflare.upbound.io", "Bucket",
            conditions=[_condition("Synced", "False", "ReconcileError")],
        ),
        _managed_object(
            "bucket-not-ready", "r2.upjet-cloudflare.upbound.io", "Bucket",
            conditions=[
                _condition("Synced", "True", "ReconcileSuccess"),
                _condition("Ready", "False", "Creating"),
            ],
        ),
        _managed_object(
            "bucket-multi-condition", "r2.upjet-cloudflare.upbound.io", "Bucket",
            conditions=[
                _condition("Synced", "False", "ReconcileError"),
                _condition("Ready", "False", "Unavailable"),
            ],
        ),
        _managed_object(
            "bucket-async-failed", "r2.upjet-cloudflare.upbound.io", "Bucket",
            conditions=[_condition("LastAsyncOperation", "False", "AsyncCreateFailure")],
        ),
        _managed_object(
            "bucket-async-failed-alt", "r2.upjet-cloudflare.upbound.io", "Bucket",
            conditions=[_condition("AsyncOperation", "False", "AsyncUpdateFailure")],
        ),
        _managed_object(
            "bucket-create-pending-stuck", "r2.upjet-cloudflare.upbound.io", "Bucket",
            annotations={"crossplane.io/external-create-pending": ago(20)},
        ),
        _managed_object(
            "bucket-create-pending-fresh", "r2.upjet-cloudflare.upbound.io", "Bucket",
            annotations={"crossplane.io/external-create-pending": ago(2)},
        ),
        _managed_object(
            "bucket-create-failed", "r2.upjet-cloudflare.upbound.io", "Bucket",
            annotations={"crossplane.io/external-create-failed": ago(5)},
        ),
        _managed_object(
            "bucket-create-succeeded-equal", "r2.upjet-cloudflare.upbound.io", "Bucket",
            annotations={
                "crossplane.io/external-create-pending": ago(20),
                "crossplane.io/external-create-succeeded": ago(20),
            },
        ),
        _managed_object(
            "bucket-create-pending-after-succeeded", "r2.upjet-cloudflare.upbound.io", "Bucket",
            annotations={
                "crossplane.io/external-create-pending": ago(20),
                "crossplane.io/external-create-succeeded": ago(30),
            },
        ),
        _managed_object(
            "bucket-create-pending-after-succeeded-fresh", "r2.upjet-cloudflare.upbound.io", "Bucket",
            annotations={
                "crossplane.io/external-create-pending": ago(2),
                "crossplane.io/external-create-succeeded": ago(5),
            },
        ),
        _managed_object(
            "bucket-create-failed-then-succeeded", "r2.upjet-cloudflare.upbound.io", "Bucket",
            annotations={
                "crossplane.io/external-create-failed": ago(30),
                "crossplane.io/external-create-succeeded": ago(10),
            },
        ),
        _managed_object(
            "bucket-create-failed-newest", "r2.upjet-cloudflare.upbound.io", "Bucket",
            annotations={
                "crossplane.io/external-create-succeeded": ago(30),
                "crossplane.io/external-create-pending": ago(20),
                "crossplane.io/external-create-failed": ago(5),
            },
        ),
        _managed_object(
            "info-simplesalt-company", "r2.upjet-cloudflare.upbound.io", "Bucket",
            conditions=[
                _condition(
                    "Synced", "False", "CannotDetermineCreationResult",
                    "cannot determine creation result",
                ),
            ],
            annotations={
                # The live shape (simplesalt/basis effort #588): succeeded is
                # older, pending is one second newer -- genuinely incomplete
                # by crossplane-runtime's own rule, so this must stay flagged.
                "crossplane.io/external-create-succeeded": "2026-09-14T12:42:56Z",
                "crossplane.io/external-create-pending": "2026-09-14T12:43:57Z",
            },
        ),
        _managed_object(
            "bucket-no-apiversion", "r2.upjet-cloudflare.upbound.io", "Bucket",
            conditions=[_condition("Synced", "False", "ReconcileError")],
            api_version=False,
        ),
        _managed_object(
            "bucket-healthy", "r2.upjet-cloudflare.upbound.io", "Bucket",
            conditions=[
                _condition("Synced", "True", "ReconcileSuccess"),
                _condition("Ready", "True", "Available"),
            ],
        ),
    ]
    client.set_resource("r2.upjet-cloudflare.upbound.io", "buckets", None, buckets)

    projects = [
        _managed_object(
            "project-ns-a", "cloudplatform.gcp.m.upbound.io", "Project", namespace="team-a",
            conditions=[_condition("Synced", "False", "ReconcileError")],
        ),
        _managed_object(
            "project-ns-b", "cloudplatform.gcp.m.upbound.io", "Project", namespace="team-b",
            conditions=[_condition("Ready", "False", "Creating")],
        ),
        _managed_object(
            "project-healthy", "cloudplatform.gcp.m.upbound.io", namespace="team-a",
            conditions=[
                _condition("Synced", "True", "ReconcileSuccess"),
                _condition("Ready", "True", "Available"),
            ],
        ),
    ]
    client.set_resource("cloudplatform.gcp.m.upbound.io", "projects", None, projects)

    providers = [
        _provider("provider-healthy", installed="True", healthy="True"),
        _provider("provider-unhealthy", installed="True", healthy="False"),
        _provider("provider-missing-deployment", installed="True", healthy="True"),
        _provider("provider-not-ready-deployment", installed="True", healthy="True"),
    ]
    client.set_resource("pkg.crossplane.io", "providers", None, providers)

    revisions = [
        _provider_revision("revision-healthy"),
        _provider_revision("revision-unhealthy", runtime_healthy="False"),
    ]
    client.set_resource("pkg.crossplane.io", "providerrevisions", None, revisions)

    # provider-missing-deployment intentionally has no matching Deployment.
    client.set_deployments(
        "crossplane-system",
        [
            _provider_deployment("provider-healthy-abc123", "provider-healthy", replicas=1, ready=1),
            _provider_deployment("provider-not-ready-abc123", "provider-not-ready-deployment", replicas=1, ready=0),
        ],
    )

    problems = crossplane.check(client, NOW)

    print("unhealthy fixture set: {} problems".format(len(problems)))
    for p in problems:
        print("  - [{}] {} {}/{}  {}".format(
            p["severity"], p["category"], p.get("namespace"), p["name"], p.get("kind")
        ))

    check(
        "Synced=False is flagged crossplane-not-synced",
        find_problem(problems, "bucket-not-synced", "crossplane-not-synced") is not None,
    )
    check(
        "Ready=False is flagged crossplane-not-ready",
        find_problem(problems, "bucket-not-ready", "crossplane-not-ready") is not None,
    )
    multi = find_problems(problems, "bucket-multi-condition")
    check(
        "an object with both Synced=False and Ready=False is flagged for each condition exactly once",
        len(multi) == 2
        and {p["category"] for p in multi} == {"crossplane-not-synced", "crossplane-not-ready"},
        "found={}".format(multi),
    )
    check(
        "LastAsyncOperation=False is flagged crossplane-async-failed",
        find_problem(problems, "bucket-async-failed", "crossplane-async-failed") is not None,
    )
    check(
        "AsyncOperation=False (alternate naming) is flagged crossplane-async-failed",
        find_problem(problems, "bucket-async-failed-alt", "crossplane-async-failed") is not None,
    )
    check(
        "external-create-pending older than the grace period is flagged crossplane-create-pending",
        find_problem(problems, "bucket-create-pending-stuck", "crossplane-create-pending") is not None,
    )
    check(
        "external-create-pending within the grace period is not flagged",
        find_problem(problems, "bucket-create-pending-fresh", "crossplane-create-pending") is None,
    )
    check(
        "external-create-failed is flagged crossplane-create-failed",
        find_problem(problems, "bucket-create-failed", "crossplane-create-failed") is not None,
    )
    check(
        "external-create-pending equal to external-create-succeeded is not flagged (equal counts as complete, per crossplane-runtime's ExternalCreateIncomplete)",
        find_problem(problems, "bucket-create-succeeded-equal", "crossplane-create-pending") is None,
    )
    pending_after_succeeded = find_problem(
        problems, "bucket-create-pending-after-succeeded", "crossplane-create-pending"
    )
    check(
        "external-create-pending strictly newer than external-create-succeeded and past grace is flagged, and its detail names the succeeded time",
        pending_after_succeeded is not None
        and "last succeeded" in pending_after_succeeded["detail"],
        "found={}".format(pending_after_succeeded),
    )
    check(
        "external-create-pending strictly newer than external-create-succeeded but still within grace is not flagged",
        find_problem(
            problems, "bucket-create-pending-after-succeeded-fresh", "crossplane-create-pending"
        )
        is None,
    )
    check(
        "external-create-failed followed by a later external-create-succeeded is flagged neither pending nor failed",
        find_problems(problems, "bucket-create-failed-then-succeeded") == [],
    )
    check(
        "external-create-failed strictly newer than both pending and succeeded is flagged crossplane-create-failed, and its pending is not also flagged",
        find_problem(problems, "bucket-create-failed-newest", "crossplane-create-failed") is not None
        and find_problem(problems, "bucket-create-failed-newest", "crossplane-create-pending") is None,
    )
    info_pending = find_problem(problems, "info-simplesalt-company", "crossplane-create-pending")
    check(
        "the live info-simplesalt-company shape (pending one second newer than succeeded, Synced=False) is flagged for both crossplane-not-synced and crossplane-create-pending, with succeeded named in the detail",
        find_problem(problems, "info-simplesalt-company", "crossplane-not-synced") is not None
        and info_pending is not None
        and "last succeeded" in info_pending["detail"],
        "found={}".format(find_problems(problems, "info-simplesalt-company")),
    )
    check(
        "a stuck object missing apiVersion falls back to its CRD's group",
        find_problem(problems, "bucket-no-apiversion", "crossplane-not-synced", ) is not None
        and find_problem(problems, "bucket-no-apiversion", "crossplane-not-synced")["apiVersion"]
        == "r2.upjet-cloudflare.upbound.io",
    )
    check(
        "a fully healthy cluster-scoped managed resource is not flagged",
        find_problems(problems, "bucket-healthy") == [],
    )
    check(
        "a namespaced managed resource (.m. group) in one namespace is flagged with its namespace carried through",
        (lambda p: p is not None and p["namespace"] == "team-a")(
            find_problem(problems, "project-ns-a", "crossplane-not-synced")
        ),
    )
    check(
        "a namespaced managed resource in a second namespace is flagged from the same single list call",
        (lambda p: p is not None and p["namespace"] == "team-b")(
            find_problem(problems, "project-ns-b", "crossplane-not-ready")
        ),
    )
    check(
        "a healthy namespaced managed resource with no explicit kind falls back to its CRD's Kind",
        find_problems(problems, "project-healthy") == [],
    )
    check(
        "a CRD that cannot be listed (RBAC denial) lands in unverifiable exactly once and does not crash the scan",
        len([e for e in client.unverifiable if "records" in e["attempted"]]) == 1
        and any("403" in e["detail"] for e in client.unverifiable if "records" in e["attempted"]),
        "unverifiable={}".format(client.unverifiable),
    )
    check(
        "a CRD without category managed is never scanned",
        not any(
            p["kind"] == "CompositeResourceDefinition" for p in problems
        ),
    )
    check(
        "Provider.Healthy=False is flagged crossplane-provider-unhealthy",
        find_problem(problems, "provider-unhealthy", "crossplane-provider-unhealthy") is not None,
    )
    check(
        "a healthy Provider with a ready runtime Deployment is not flagged",
        find_problems(problems, "provider-healthy") == [],
    )
    check(
        "Provider.Healthy=True with an absent runtime Deployment is flagged crossplane-provider-runtime-missing",
        find_problem(problems, "provider-missing-deployment", "crossplane-provider-runtime-missing") is not None,
    )
    check(
        "Provider.Healthy=True with a runtime Deployment that has no ready replicas is flagged crossplane-provider-runtime-missing",
        find_problem(problems, "provider-not-ready-deployment", "crossplane-provider-runtime-missing") is not None,
    )
    check(
        "ProviderRevision.RuntimeHealthy=False (v2-style condition, not Installed/Healthy) is flagged crossplane-provider-unhealthy",
        find_problem(problems, "revision-unhealthy", "crossplane-provider-unhealthy") is not None,
    )
    check(
        "a healthy ProviderRevision is not flagged",
        find_problems(problems, "revision-healthy") == [],
    )

    return problems


# --- healthy fixture set: zero problems -----------------------------------


def run_healthy():
    client = FakeClient()

    crd = _crd("r2.upjet-cloudflare.upbound.io", "buckets", "Bucket", "Cluster")
    client.set_resource("apiextensions.k8s.io", "customresourcedefinitions", None, [crd])
    client.set_resource(
        "r2.upjet-cloudflare.upbound.io", "buckets", None,
        [
            _managed_object(
                "healthy-bucket", "r2.upjet-cloudflare.upbound.io", "Bucket",
                conditions=[
                    _condition("Synced", "True", "ReconcileSuccess"),
                    _condition("Ready", "True", "Available"),
                ],
            )
        ],
    )

    client.set_resource(
        "pkg.crossplane.io", "providers", None,
        [_provider("healthy-provider", installed="True", healthy="True")],
    )
    client.set_resource(
        "pkg.crossplane.io", "providerrevisions", None,
        [_provider_revision("healthy-revision")],
    )
    client.set_deployments(
        "crossplane-system",
        [_provider_deployment("healthy-provider-abc123", "healthy-provider", replicas=1, ready=1)],
    )

    problems = crossplane.check(client, NOW)
    print("healthy fixture set: {} problems".format(len(problems)))

    check(
        "a fully healthy fixture set returns zero problems",
        problems == [],
        "found={}".format(problems),
    )
    check(
        "a fully healthy fixture set records nothing unverifiable",
        client.unverifiable == [],
        "unverifiable={}".format(client.unverifiable),
    )

    return problems


def run():
    run_unhealthy()
    print()
    run_healthy()

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
