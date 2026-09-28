#!/usr/bin/env python3
"""Local test for platform/cluster-health's flux.check(), no cluster access.

Same approach as test-cluster-health.py (which covers finalizers.check()):
runs flux.check() against a FakeClient loaded with fixture Kubernetes
objects instead of the real client.py. FakeClient implements the one
method flux.py actually calls (list_resource) plus .unverifiable, and
counts calls per (group, resource, namespace) so the "list once, reuse"
API-call bound can be asserted directly.

Four scenarios:

1. run_conditions() -- one object per problem category flux.check() can
   report (flux-not-ready, flux-retrying, flux-generation-lag,
   flux-reconcile-request-unhandled, flux-history-failures,
   flux-source-stale, flux-suspended, flux-reconcile-disabled), each
   firing exactly once; a request-grace case that should NOT fire; a
   Secret inventory entry that must be skipped silently; a denied
   ConfigMap lookup that must land in unverifiable once; and a second
   Kustomization sharing the same inventory (group, resource) pair to
   prove it is listed once and reused, not once per entry. The
   flux-history-failures instance here is the HelmRelease example from
   the parent Effort's request: kube-prometheus-stack with 9 failed
   releases 2026-09-12..21 before recovering to Ready=True. The
   flux-source-stale instance here is a GitRepository with FetchFailed=True
   -- the conditions-based replacement for the old artifact-age heuristic.
2. run_kustomization_flapping() -- isolates Kustomization-side flapping
   (status.history's lastReconciledStatus/ReconciliationSucceeded shape,
   distinct from HelmRelease's status/failed shape) in its own fixture so
   it does not collide with scenario 1's "exactly once" counts.
3. run_source_conditions() -- isolates the source-specific fixes: an
   OCI-type HelmRepository reporting no Ready condition at all (the live
   shape of flux-system/simplesalt-charts) must not be flagged, but one
   that does report Ready=False still is; a non-OCI HelmRepository with no
   Ready condition is unaffected by that exemption; an idle source with
   healthy conditions and no recent artifact update (the live shape of
   flux-system/ss-cloud-basis, which the old age heuristic flagged stale at
   ~8h old on a 1m interval) is never flagged; and a source with
   Stalled=True is flagged even while Ready is still True.
4. run_healthy() -- one object of every kind, all clean, expects zero
   problems and an empty unverifiable list.

    scripts/test-cluster-health-flux.py
"""

import os
import sys
import traceback
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "platform", "cluster-health"))

import flux  # noqa: E402

NOW = datetime.now(timezone.utc).replace(microsecond=0)


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def ago(minutes):
    return iso(NOW - timedelta(minutes=minutes))


class FakeClient:
    """A fixture-backed stand-in for client.Client, covering only the
    surface flux.py calls: list_resource and .unverifiable.

    deny_resource simulates an RBAC 403 (or any other failed call) the way
    client.py's get_safe records one: append to self.unverifiable and
    return None instead of raising. calls counts every list_resource
    invocation per (group, resource, namespace) key so a test can assert
    a kind was listed once and reused rather than once per object.
    """

    def __init__(self):
        self.unverifiable = []
        self.calls = {}
        self._resources = {}
        self._deny = {}

    def set_resource(self, group, resource, namespace, items):
        self._resources[(group, resource, namespace)] = items

    def deny_resource(self, group, resource, namespace, detail="403 Forbidden"):
        self._deny[(group, resource, namespace)] = detail

    def list_resource(self, group, resource, namespace=None):
        key = (group, resource, namespace)
        self.calls[key] = self.calls.get(key, 0) + 1
        if key in self._deny:
            scope = "namespace {}".format(namespace) if namespace else "cluster-wide"
            attempted = "list {}{} ({})".format(
                resource, "." + group if group else "", scope
            )
            self.unverifiable.append(
                {"attempted": attempted, "detail": self._deny[key]}
            )
            return None
        return self._resources.get(key, [])


# --- fixture builders ---------------------------------------------------


def _kustomization(
    name,
    namespace="flux-system",
    ready_status="True",
    ready_reason="ReconciliationSucceeded",
    reconciling=None,
    generation=1,
    observed_generation=1,
    suspend=False,
    requested_at=None,
    handled_at=None,
    history=None,
    inventory_entries=None,
):
    conditions = [
        {"type": "Ready", "status": ready_status, "reason": ready_reason, "message": "..."}
    ]
    if reconciling is not None:
        conditions.append(reconciling)
    metadata = {"name": name, "namespace": namespace, "generation": generation}
    if requested_at is not None:
        metadata["annotations"] = {"reconcile.fluxcd.io/requestedAt": requested_at}
    status = {"conditions": conditions, "observedGeneration": observed_generation}
    if handled_at is not None:
        status["lastHandledReconcileAt"] = handled_at
    if history is not None:
        status["history"] = history
    if inventory_entries is not None:
        status["inventory"] = {"entries": inventory_entries}
    return {
        "apiVersion": "kustomize.toolkit.fluxcd.io/v1",
        "kind": "Kustomization",
        "metadata": metadata,
        "spec": {"suspend": suspend},
        "status": status,
    }


def _helmrelease(
    name,
    namespace="flux-system",
    ready_status="True",
    ready_reason="InstallSucceeded",
    history=None,
    suspend=False,
):
    conditions = [
        {"type": "Ready", "status": ready_status, "reason": ready_reason, "message": "..."}
    ]
    status = {"conditions": conditions}
    if history is not None:
        status["history"] = history
    return {
        "apiVersion": "helm.toolkit.fluxcd.io/v2",
        "kind": "HelmRelease",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {"suspend": suspend},
        "status": status,
    }


def _source(
    kind,
    name,
    namespace="flux-system",
    ready_status="True",
    ready_reason="Succeeded",
    interval="10m",
    suspend=False,
    source_type=None,
    no_ready_condition=False,
    extra_conditions=None,
):
    """A source fixture. no_ready_condition=True omits the Ready condition
    entirely (status: {} -- the real shape of an OCI-type HelmRepository,
    e.g. flux-system/simplesalt-charts, confirmed live). source_type sets
    spec.type (e.g. "oci"). extra_conditions appends condition dicts such
    as FetchFailed/Stalled. No status.artifact is ever set here -- the
    conditions-based health check (see flux.py's _source_condition_problem)
    never reads it, unlike the artifact-age heuristic it replaced."""
    conditions = []
    if not no_ready_condition:
        conditions.append(
            {"type": "Ready", "status": ready_status, "reason": ready_reason, "message": "..."}
        )
    if extra_conditions:
        conditions.extend(extra_conditions)
    spec = {"interval": interval, "suspend": suspend}
    if source_type is not None:
        spec["type"] = source_type
    return {
        "apiVersion": "source.toolkit.fluxcd.io/v1",
        "kind": kind,
        "metadata": {"name": name, "namespace": namespace},
        "spec": spec,
        "status": {"conditions": conditions} if conditions else {},
    }


def _deployment(name, namespace, annotations=None):
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": name, "namespace": namespace, "annotations": annotations or {}},
        "spec": {},
        "status": {},
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


def count_category(problems, category):
    return sum(1 for p in problems if p.get("category") == category)


# --- scenario 1: every category, each firing exactly once ---------------


def run_conditions():
    print("-- scenario: one problem per category, each exactly once --")
    client = FakeClient()

    ks_not_ready = _kustomization("ks-not-ready", ready_status="False", ready_reason="HealthCheckFailed")

    ks_retrying = _kustomization(
        "ks-retrying",
        reconciling={
            "type": "Reconciling",
            "status": "True",
            "reason": "ProgressingWithRetry",
            "message": "retrying apply after failure",
        },
    )

    ks_gen_lag = _kustomization("ks-gen-lag", generation=3, observed_generation=2)

    ks_request_unhandled = _kustomization(
        "ks-request-unhandled", requested_at=ago(10), handled_at=ago(60)
    )

    # Within the grace period -- must NOT be flagged.
    ks_request_recent = _kustomization(
        "ks-request-recent", requested_at=ago(1), handled_at=ago(60)
    )

    ks_suspended = _kustomization("ks-suspended", suspend=True)

    ks_inventory = _kustomization(
        "ks-inventory",
        inventory_entries=[
            {"id": "apps_protected-app_apps_Deployment", "v": "v1"},
            {"id": "apps_protected-secret__Secret", "v": "v1"},
            {"id": "apps_denied-cm__ConfigMap", "v": "v1"},
        ],
    )
    # A second Kustomization referencing the same (group, resource) pair
    # (apps/Deployment) -- list_resource for it must be called once total,
    # not once per Kustomization or once per entry.
    ks_inventory_2 = _kustomization(
        "ks-inventory-2",
        inventory_entries=[{"id": "apps2_protected-app-2_apps_Deployment", "v": "v1"}],
    )

    client.set_resource(
        "kustomize.toolkit.fluxcd.io",
        "kustomizations",
        None,
        [
            ks_not_ready,
            ks_retrying,
            ks_gen_lag,
            ks_request_unhandled,
            ks_request_recent,
            ks_suspended,
            ks_inventory,
            ks_inventory_2,
        ],
    )

    protected_app = _deployment(
        "protected-app", "apps", annotations={"kustomize.toolkit.fluxcd.io/reconcile": "disabled"}
    )
    protected_app_2 = _deployment("protected-app-2", "apps2")  # healthy, no annotation
    client.set_resource("apps", "deployments", None, [protected_app, protected_app_2])
    client.deny_resource(
        "", "configmaps", None, detail="403 Forbidden: configmaps is forbidden"
    )

    # HelmRelease flapping example straight from the parent Effort's
    # request: kube-prometheus-stack had 9 failed releases 2026-09-12..21
    # then recovered to Ready=True.
    hr_history_flapping = _helmrelease(
        "kube-prometheus-stack",
        namespace="monitoring",
        history=[
            {"status": "failed", "firstDeployed": "2026-09-12T00:00:00Z", "lastDeployed": "2026-09-12T00:10:00Z"},
            {"status": "failed", "firstDeployed": "2026-09-13T00:00:00Z", "lastDeployed": "2026-09-13T00:10:00Z"},
            {"status": "failed", "firstDeployed": "2026-09-14T00:00:00Z", "lastDeployed": "2026-09-14T00:10:00Z"},
            {"status": "failed", "firstDeployed": "2026-09-15T00:00:00Z", "lastDeployed": "2026-09-15T00:10:00Z"},
            {"status": "failed", "firstDeployed": "2026-09-16T00:00:00Z", "lastDeployed": "2026-09-16T00:10:00Z"},
            {"status": "failed", "firstDeployed": "2026-09-17T00:00:00Z", "lastDeployed": "2026-09-17T00:10:00Z"},
            {"status": "failed", "firstDeployed": "2026-09-18T00:00:00Z", "lastDeployed": "2026-09-18T00:10:00Z"},
            {"status": "failed", "firstDeployed": "2026-09-19T00:00:00Z", "lastDeployed": "2026-09-19T00:10:00Z"},
            {"status": "failed", "firstDeployed": "2026-09-21T00:00:00Z", "lastDeployed": "2026-09-21T00:10:00Z"},
            {"status": "deployed", "firstDeployed": "2026-09-22T00:00:00Z", "lastDeployed": "2026-09-22T00:10:00Z"},
        ],
    )
    client.set_resource("helm.toolkit.fluxcd.io", "helmreleases", None, [hr_history_flapping])

    src_fetch_failed = _source(
        "GitRepository",
        "src-fetch-failed",
        interval="10m",
        extra_conditions=[
            {
                "type": "FetchFailed",
                "status": "True",
                "reason": "GitOperationFailed",
                "message": "unable to clone: authentication required",
            }
        ],
    )
    client.set_resource("source.toolkit.fluxcd.io", "gitrepositories", None, [src_fetch_failed])

    problems = flux.check(client, NOW)

    print("problems found: {}".format(len(problems)))
    for p in problems:
        print(
            "  - {} {} {}/{}  category={}  severity={}".format(
                p["category"], p["kind"], p.get("namespace"), p["name"], p["category"], p["severity"]
            )
        )

    check("exactly 8 problems reported", len(problems) == 8, "found {}".format(len(problems)))

    not_ready = find_problem(problems, "ks-not-ready")
    check(
        "Ready!=True on a Kustomization is flux-not-ready, severity critical, exactly once",
        not_ready is not None
        and not_ready["category"] == "flux-not-ready"
        and not_ready["severity"] == "critical"
        and count_category(problems, "flux-not-ready") == 1,
        "found={}".format(not_ready),
    )

    retrying = find_problem(problems, "ks-retrying")
    check(
        "Reconciling=True reason=ProgressingWithRetry is flux-retrying, exactly once",
        retrying is not None
        and retrying["category"] == "flux-retrying"
        and retrying["severity"] == "warning"
        and count_category(problems, "flux-retrying") == 1,
        "found={}".format(retrying),
    )

    gen_lag = find_problem(problems, "ks-gen-lag")
    check(
        "observedGeneration behind generation is flux-generation-lag, exactly once",
        gen_lag is not None
        and gen_lag["category"] == "flux-generation-lag"
        and count_category(problems, "flux-generation-lag") == 1,
        "found={}".format(gen_lag),
    )

    unhandled = find_problem(problems, "ks-request-unhandled")
    check(
        "a requestedAt not yet in lastHandledReconcileAt past the grace period is "
        "flux-reconcile-request-unhandled, exactly once",
        unhandled is not None
        and unhandled["category"] == "flux-reconcile-request-unhandled"
        and count_category(problems, "flux-reconcile-request-unhandled") == 1,
        "found={}".format(unhandled),
    )

    check(
        "a requestedAt still within the grace period is not flagged",
        find_problem(problems, "ks-request-recent") is None,
        "found={}".format(find_problem(problems, "ks-request-recent")),
    )

    flapping_hr = find_problem(problems, "kube-prometheus-stack")
    check(
        "a HelmRelease with failed history entries is flux-history-failures even "
        "though Ready is currently True, with count and first/last times, exactly once",
        flapping_hr is not None
        and flapping_hr["category"] == "flux-history-failures"
        and flapping_hr["kind"] == "HelmRelease"
        and flapping_hr["count"] == 9
        and flapping_hr["first_time"] == "2026-09-12T00:10:00Z"
        and flapping_hr["last_time"] == "2026-09-21T00:10:00Z"
        and count_category(problems, "flux-history-failures") == 1,
        "found={}".format(flapping_hr),
    )

    stale = find_problem(problems, "src-fetch-failed")
    check(
        "a source with FetchFailed=True is flux-source-stale -- conditions-"
        "based, not an artifact-age heuristic -- exactly once",
        stale is not None
        and stale["category"] == "flux-source-stale"
        and stale["kind"] == "GitRepository"
        and count_category(problems, "flux-source-stale") == 1,
        "found={}".format(stale),
    )

    suspended = find_problem(problems, "ks-suspended")
    check(
        "spec.suspend=true is flux-suspended, exactly once",
        suspended is not None
        and suspended["category"] == "flux-suspended"
        and count_category(problems, "flux-suspended") == 1,
        "found={}".format(suspended),
    )

    disabled = find_problem(problems, "protected-app")
    check(
        "an inventory object annotated reconcile: disabled is flux-reconcile-disabled, "
        "naming its owning Kustomization, exactly once",
        disabled is not None
        and disabled["category"] == "flux-reconcile-disabled"
        and disabled["kind"] == "Deployment"
        and disabled["namespace"] == "apps"
        and disabled["kustomization_name"] == "ks-inventory"
        and count_category(problems, "flux-reconcile-disabled") == 1,
        "found={}".format(disabled),
    )

    check(
        "the healthy inventory object referenced from a second Kustomization is not flagged",
        find_problem(problems, "protected-app-2") is None,
        "found={}".format(find_problem(problems, "protected-app-2")),
    )

    check(
        "a Secret inventory entry is skipped silently -- no unverifiable entry mentions it",
        not any("secret" in entry["attempted"].lower() for entry in client.unverifiable),
        "unverifiable={}".format(client.unverifiable),
    )

    check(
        "a denied ConfigMap inventory lookup lands in unverifiable once",
        sum(1 for entry in client.unverifiable if "configmaps" in entry["attempted"]) == 1,
        "unverifiable={}".format(client.unverifiable),
    )

    check(
        "apps/Deployment is listed once cluster-wide and reused across both "
        "Kustomizations' inventories, not once per entry",
        client.calls.get(("apps", "deployments", None)) == 1,
        "calls={}".format(client.calls),
    )

    print()


# --- scenario 2: Kustomization-side history flapping, in isolation ------


def run_kustomization_flapping():
    print("-- scenario: Kustomization status.history flapping --")
    client = FakeClient()

    # Kustomization history entries carry firstReconciled/lastReconciled
    # (confirmed live), not "lastReconciledAt" -- see flux.py's
    # _check_kustomization. Each entry here uses a distinct
    # firstReconciled/lastReconciled pair so the assertion below can prove
    # the real fields are read (a bug that always returns None for both
    # would print "first=None last=None" and still pass a same-valued test).
    ks_flapping = _kustomization(
        "ks-flapping",
        history=[
            {
                "lastReconciledStatus": "ReconciliationFailed",
                "firstReconciled": ago(125),
                "lastReconciled": ago(120),
            },
            {
                "lastReconciledStatus": "ReconciliationFailed",
                "firstReconciled": ago(95),
                "lastReconciled": ago(90),
            },
            {
                "lastReconciledStatus": "ReconciliationSucceeded",
                "firstReconciled": ago(15),
                "lastReconciled": ago(10),
            },
        ],
    )
    client.set_resource("kustomize.toolkit.fluxcd.io", "kustomizations", None, [ks_flapping])

    problems = flux.check(client, NOW)
    print("problems found: {}".format(len(problems)))

    check(
        "a Kustomization with failed history entries alongside a current success "
        "is flux-history-failures, with real first/last reconciled times (not "
        "\"first=None last=None\")",
        len(problems) == 1
        and problems[0]["category"] == "flux-history-failures"
        and problems[0]["kind"] == "Kustomization"
        and problems[0]["name"] == "ks-flapping"
        and problems[0]["count"] == 2
        and problems[0]["first_time"] == ago(120)
        and problems[0]["last_time"] == ago(90)
        and "None" not in problems[0]["detail"],
        "problems={}".format(problems),
    )

    print()


# --- scenario 3: source health via conditions, not artifact age ---------


def run_source_conditions():
    print("-- scenario: source health via conditions, not artifact age --")
    client = FakeClient()

    # (a) An OCI-type HelmRepository reports no Ready condition at all by
    # design (confirmed live: flux-system/simplesalt-charts has status: {})
    # -- must not be flagged critical flux-not-ready for that alone, and
    # has no other bad condition either, so it gets zero problems.
    oci_no_ready = _source("HelmRepository", "oci-quiet", source_type="oci", no_ready_condition=True)

    # (a), second half: an OCI HelmRepository that DOES report Ready=False
    # is still flagged -- the skip is only for the no-condition case.
    oci_ready_false = _source(
        "HelmRepository", "oci-broken", source_type="oci",
        ready_status="False", ready_reason="ChartPullFailed",
    )

    # The (a) exemption is OCI-only: a plain (non-OCI) HelmRepository with
    # no Ready condition is still flagged flux-not-ready, same as before.
    plain_no_ready = _source("HelmRepository", "plain-quiet", no_ready_condition=True)

    client.set_resource(
        "source.toolkit.fluxcd.io",
        "helmrepositories",
        None,
        [oci_no_ready, oci_ready_false, plain_no_ready],
    )

    # (b) An idle source with healthy conditions and no recent artifact
    # update -- the live shape of flux-system/ss-cloud-basis, which the old
    # artifact-age heuristic flagged stale at ~8h old on a 1m interval
    # simply because its revision hadn't changed. No status.artifact is
    # even set here, to make the point sharply: age is never consulted.
    idle_but_healthy = _source("GitRepository", "idle-but-healthy", interval="1m")
    client.set_resource("source.toolkit.fluxcd.io", "gitrepositories", None, [idle_but_healthy])

    # (b) A source with Stalled=True -- a terminal failure Flux won't retry
    # without intervention -- is flagged even while Ready is still True.
    stalled = _source(
        "Bucket",
        "src-stalled",
        ready_status="True",
        extra_conditions=[
            {
                "type": "Stalled",
                "status": "True",
                "reason": "InvalidBucketName",
                "message": "bucket name is invalid",
            }
        ],
    )
    client.set_resource("source.toolkit.fluxcd.io", "buckets", None, [stalled])

    problems = flux.check(client, NOW)
    print("problems found: {}".format(len(problems)))
    for p in problems:
        print(
            "  - {} {} {}/{}  category={}".format(
                p["category"], p["kind"], p.get("namespace"), p["name"], p["category"]
            )
        )

    check("exactly 4 problems reported", len(problems) == 4, "found {}".format(len(problems)))

    check(
        "an OCI HelmRepository with no Ready condition at all is not flagged "
        "at all (no flux-not-ready, no flux-source-stale)",
        find_problem(problems, "oci-quiet") is None,
        "found={}".format(find_problem(problems, "oci-quiet")),
    )

    oci_broken = find_problem(problems, "oci-broken")
    check(
        "an OCI HelmRepository that DOES report Ready=False is still "
        "flagged flux-not-ready, critical",
        oci_broken is not None
        and oci_broken["category"] == "flux-not-ready"
        and oci_broken["severity"] == "critical",
        "found={}".format(oci_broken),
    )
    check(
        "the same Ready=False HelmRepository is also flagged flux-source-stale "
        "via the new conditions-based check",
        any(p["name"] == "oci-broken" and p["category"] == "flux-source-stale" for p in problems),
        "problems={}".format(problems),
    )

    plain_broken = find_problem(problems, "plain-quiet")
    check(
        "a non-OCI HelmRepository with no Ready condition is still flagged "
        "flux-not-ready -- the (a) exemption is OCI-only",
        plain_broken is not None and plain_broken["category"] == "flux-not-ready",
        "found={}".format(plain_broken),
    )

    check(
        "an idle source with healthy conditions and no recent artifact update "
        "is never flagged flux-source-stale -- age is no longer consulted",
        find_problem(problems, "idle-but-healthy") is None,
        "found={}".format(find_problem(problems, "idle-but-healthy")),
    )

    stalled_problem = find_problem(problems, "src-stalled")
    check(
        "a source with Stalled=True is flagged flux-source-stale even while "
        "Ready is still True",
        stalled_problem is not None and stalled_problem["category"] == "flux-source-stale",
        "found={}".format(stalled_problem),
    )

    print()


# --- scenario 4: a healthy fixture set reports nothing -------------------


def run_healthy():
    print("-- scenario: healthy fixture set --")
    client = FakeClient()

    same_ts = ago(120)
    ks_healthy = _kustomization(
        "ks-healthy",
        generation=5,
        observed_generation=5,
        requested_at=same_ts,
        handled_at=same_ts,
        history=[{"lastReconciledStatus": "ReconciliationSucceeded", "firstReconciled": ago(6), "lastReconciled": ago(5)}],
        inventory_entries=[
            {"id": "apps_healthy-app_apps_Deployment", "v": "v1"},
            {"id": "apps_healthy-secret__Secret", "v": "v1"},
        ],
    )
    client.set_resource("kustomize.toolkit.fluxcd.io", "kustomizations", None, [ks_healthy])

    hr_healthy = _helmrelease(
        "hr-healthy",
        history=[{"status": "deployed", "firstDeployed": ago(200), "lastDeployed": ago(190)}],
    )
    client.set_resource("helm.toolkit.fluxcd.io", "helmreleases", None, [hr_healthy])

    client.set_resource(
        "source.toolkit.fluxcd.io",
        "gitrepositories",
        None,
        [_source("GitRepository", "git-healthy", interval="10m")],
    )
    # helmrepo-healthy is an ordinary HelmRepository; oci-healthy is an
    # OCI-type HelmRepository reporting no Ready condition at all (the live
    # shape of flux-system/simplesalt-charts) -- also a healthy case now,
    # must not contribute any problem to this scenario's "zero problems"
    # expectation.
    client.set_resource(
        "source.toolkit.fluxcd.io",
        "helmrepositories",
        None,
        [
            _source("HelmRepository", "helmrepo-healthy", interval="1h"),
            _source("HelmRepository", "oci-healthy", source_type="oci", no_ready_condition=True),
        ],
    )
    client.set_resource(
        "source.toolkit.fluxcd.io",
        "ocirepositories",
        None,
        [_source("OCIRepository", "ocirepo-healthy", interval="30m")],
    )
    client.set_resource(
        "source.toolkit.fluxcd.io",
        "buckets",
        None,
        [_source("Bucket", "bucket-healthy", interval="15m")],
    )

    client.set_resource("apps", "deployments", None, [_deployment("healthy-app", "apps")])

    problems = flux.check(client, NOW)
    print("problems found: {}".format(len(problems)))

    check("a fully healthy fixture set reports zero problems", problems == [], "problems={}".format(problems))
    check("a fully healthy run never touches unverifiable", client.unverifiable == [], "unverifiable={}".format(client.unverifiable))

    print()


def run():
    run_conditions()
    run_kustomization_flapping()
    run_source_conditions()
    run_healthy()

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
