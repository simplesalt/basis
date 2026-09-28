#!/usr/bin/env python3
"""Local test for client.py's per-run list cache, no cluster access.

The other test scripts (test-cluster-health.py, -flux.py, -crossplane.py,
-alerts.py, -nodes.py, -stale.py) each run one check module against a
hand-rolled FakeClient that stands in for client.Client entirely, so none of
them exercise client.py's own caching -- they just implement
list_resource/list_deployments/group_resources as plain dict lookups. This
script instead exercises the real client.Client (the one server.py's
run_checks actually constructs per /health call), with only its HTTP layer
(Client.get) replaced by a fixture-backed fake, so the real
discovery/list/cache code paths run.

That real Client is then shared across finalizers.check, flux.check,
crossplane.check, alerts.check, nodes.check and stale.check the same way
server.py's run_checks shares one Client across all six
(CHECKS = (finalizers, flux, crossplane, alerts, nodes, stale)), and every
fake GET is counted by path. The point: finalizers.py's and stale.py's
widened scans list several (group, resource) pairs -- CustomResourceDefinitions,
Kustomizations, HelmReleases, the four Source kinds, Providers,
ProviderRevisions, Deployments, Nodes -- that more than one of these modules
ask for, and client.py's list cache must make each one a single real HTTP
call shared across every module that asks, not one call per module.
Prometheus (alerts.py, nodes.py) is faked separately, via a FakePrometheus
stashed on client.prometheus (the same injection point prometheus.py's
own for_client docstring describes), so this script never makes a real
HTTP call to Prometheus either.

Bypasses Client.__init__ (it reads a ServiceAccount token/CA file that don't
exist here) via Client.__new__ plus manually setting the handful of instance
attributes __init__ would have, then overrides the `get` method with a
fixture function -- so `resolve`/`_discover_group`/`list_resource`/
`list_deployments` all run for real against canned discovery and list
bodies shaped like a real apiserver's, rather than being faked out
themselves.

A second scenario, run_retry(), covers Client.get's 429 (TooManyRequests)
retry separately: it overrides only `_fetch` (the single HTTP attempt `get`
now wraps in a retry loop), not `get` itself, so `get`'s real retry logic
runs against a fixture that fails a controlled number of times -- proving a
429 that clears within two retries succeeds silently, one that never
clears still lands in unverifiable (just after retrying), and a non-429
failure is never retried.

    scripts/test-cluster-health-client-cache.py
"""

import os
import sys
import traceback
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "platform", "cluster-health"))

import alerts
import client as client_mod  # noqa: E402
import crossplane  # noqa: E402
import finalizers  # noqa: E402
import flux  # noqa: E402
import nodes
import stale

NOW = datetime.now(timezone.utc).replace(microsecond=0)


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def ago(minutes):
    return iso(NOW - timedelta(minutes=minutes))


def _resource(name, kind, namespaced, verbs=("get", "list", "watch")):
    return {"name": name, "kind": kind, "namespaced": namespaced, "verbs": list(verbs)}


def _preferred(version):
    return {"preferredVersion": {"version": version}}


# A small fake cluster: just enough discovery + list fixtures to exercise
# every (group, resource) finalizers.py's widened scan, flux.py and
# crossplane.py actually ask for, plus one stuck object (a postgresql.cnpg.io
# Cluster) proving the widened scan finds an extra kind end-to-end through
# the real Client -- and one resource with no "list" verb (Backup), proving
# discovery's verb filter keeps it out of group_resources()/list_resource()
# entirely.
STUCK_CLUSTER = {
    "apiVersion": "postgresql.cnpg.io/v1",
    "kind": "Cluster",
    "metadata": {
        "name": "stuck-pg",
        "namespace": "cluster-main-observability",
        "deletionTimestamp": ago(30),
        "finalizers": ["cnpg.io/finalizer"],
    },
}

HEALTHY_NODE = {
    "apiVersion": "v1",
    "kind": "Node",
    "metadata": {"name": "k-fixture-healthy"},
    "spec": {"unschedulable": False},
    "status": {
        "conditions": [
            {
                "type": "Ready",
                "status": "True",
                "reason": "KubeletReady",
                "message": "kubelet is posting ready status",
                "lastTransitionTime": ago(60),
            }
        ]
    },
}

RESPONSES = {
    # -- core (v1) --
    "/api/v1": {
        "resources": [
            _resource("namespaces", "Namespace", False),
            _resource("nodes", "Node", False),
            _resource("pods", "Pod", True),
            _resource("persistentvolumes", "PersistentVolume", False),
            _resource("persistentvolumeclaims", "PersistentVolumeClaim", True),
        ]
    },
    "/api/v1/namespaces": {"items": []},
    "/api/v1/nodes": {"items": [HEALTHY_NODE]},
    "/api/v1/pods": {"items": []},
    "/api/v1/persistentvolumes": {"items": []},
    "/api/v1/persistentvolumeclaims": {"items": []},
    # -- apps/v1 --
    "/apis/apps": _preferred("v1"),
    "/apis/apps/v1": {
        "resources": [
            _resource("deployments", "Deployment", True),
            _resource("daemonsets", "DaemonSet", True),
        ]
    },
    "/apis/apps/v1/deployments": {"items": []},
    "/apis/apps/v1/namespaces/crossplane-system/deployments": {"items": []},
    "/apis/apps/v1/namespaces/cnpg-system/deployments": {"items": []},
    "/apis/apps/v1/namespaces/kured/daemonsets": {"items": []},
    "/apis/discovery.k8s.io": _preferred("v1"),
    "/apis/discovery.k8s.io/v1": {
        "resources": [_resource("endpointslices", "EndpointSlice", True)]
    },
    "/apis/discovery.k8s.io/v1/endpointslices": {"items": []},
    "/apis/admissionregistration.k8s.io": _preferred("v1"),
    "/apis/admissionregistration.k8s.io/v1": {
        "resources": [
            _resource("validatingwebhookconfigurations", "ValidatingWebhookConfiguration", False),
            _resource("mutatingwebhookconfigurations", "MutatingWebhookConfiguration", False),
        ]
    },
    "/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations": {"items": []},
    "/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations": {"items": []},
    # -- apiextensions.k8s.io/v1 --
    "/apis/apiextensions.k8s.io": _preferred("v1"),
    "/apis/apiextensions.k8s.io/v1": {
        "resources": [_resource("customresourcedefinitions", "CustomResourceDefinition", False)]
    },
    "/apis/apiextensions.k8s.io/v1/customresourcedefinitions": {"items": []},
    # -- Flux --
    "/apis/kustomize.toolkit.fluxcd.io": _preferred("v1"),
    "/apis/kustomize.toolkit.fluxcd.io/v1": {
        "resources": [_resource("kustomizations", "Kustomization", True)]
    },
    "/apis/kustomize.toolkit.fluxcd.io/v1/kustomizations": {"items": []},
    "/apis/helm.toolkit.fluxcd.io": _preferred("v2"),
    "/apis/helm.toolkit.fluxcd.io/v2": {
        "resources": [_resource("helmreleases", "HelmRelease", True)]
    },
    "/apis/helm.toolkit.fluxcd.io/v2/helmreleases": {"items": []},
    "/apis/source.toolkit.fluxcd.io": _preferred("v1"),
    "/apis/source.toolkit.fluxcd.io/v1": {
        "resources": [
            _resource("gitrepositories", "GitRepository", True),
            _resource("helmrepositories", "HelmRepository", True),
            _resource("ocirepositories", "OCIRepository", True),
            _resource("buckets", "Bucket", True),
        ]
    },
    "/apis/source.toolkit.fluxcd.io/v1/gitrepositories": {"items": []},
    "/apis/source.toolkit.fluxcd.io/v1/helmrepositories": {"items": []},
    "/apis/source.toolkit.fluxcd.io/v1/ocirepositories": {"items": []},
    "/apis/source.toolkit.fluxcd.io/v1/buckets": {"items": []},
    # -- Crossplane core --
    "/apis/pkg.crossplane.io": _preferred("v1"),
    "/apis/pkg.crossplane.io/v1": {
        "resources": [
            _resource("providers", "Provider", False),
            _resource("providerrevisions", "ProviderRevision", False),
        ]
    },
    "/apis/pkg.crossplane.io/v1/providers": {"items": []},
    "/apis/pkg.crossplane.io/v1/providerrevisions": {"items": []},
    # -- an extra Kind only reachable via the widened full scan; "backups"
    # has no "list" verb and must never be requested at all --
    "/apis/postgresql.cnpg.io": _preferred("v1"),
    "/apis/postgresql.cnpg.io/v1": {
        "resources": [
            _resource("clusters", "Cluster", True),
            _resource("backups", "Backup", True, verbs=("get",)),
        ]
    },
    "/apis/postgresql.cnpg.io/v1/clusters": {"items": [STUCK_CLUSTER]},
}

# Every other PROACTIVE_GROUPS group (apiextensions.crossplane.io, the
# cloudplatform.gcp.*/gcp.*/dns.*/r2.*/upjet-cloudflare.*/workers.*/zero.*
# Crossplane provider groups, fluentbit.fluent.io, cert-manager.io,
# kyverno.io) is deliberately left out of RESPONSES: fake_get below treats a
# missing "/apis/<group>" doc as a 404, i.e. a group genuinely not
# registered in this fake cluster -- exactly like a real apiserver's 404 for
# an unregistered group. That exercises the same "absent -> group_resources
# returns [] -> skip" path client.py already has, without needing fixtures
# for groups this test has nothing to say about.


def make_fake_get(calls):
    def fake_get(path, params=None):
        calls[path] = calls.get(path, 0) + 1
        if path in RESPONSES:
            return RESPONSES[path]
        if path.startswith("/apis/") and path.count("/") == 2:
            # An unfixtured "/apis/<group>" doc: treat as a group this fake
            # cluster does not have installed, same as a real 404.
            raise client_mod.ApiError(
                "GET", path, 404, "the server could not find the requested resource"
            )
        raise AssertionError(
            "fake_get: no fixture for {!r} -- add one to RESPONSES "
            "(this is a test-fixture gap, not necessarily a code bug)".format(path)
        )

    return fake_get


class FakePrometheus:
    """Stand-in for prometheus.Prometheus, injected on client.prometheus the
    same way prometheus.for_client's own docstring says a real caller (or a
    test) would -- so alerts.check/nodes.check read canned data here instead
    of ever making a real HTTP call to Prometheus. No node in this fake
    cluster is cordoned (see HEALTHY_NODE), so nodes.py never calls .query()
    at all; alerts.py calls .alerts() exactly once."""

    def __init__(self, alerts_list=None):
        self._alerts_list = alerts_list or []
        self.alert_calls = 0
        self.query_calls = 0

    def alerts(self):
        self.alert_calls += 1
        return self._alerts_list

    def query(self, expr):
        self.query_calls += 1
        return []


def make_client():
    calls = {}
    c = client_mod.Client.__new__(client_mod.Client)
    c.unverifiable = []
    c._discovery_cache = {}
    c._deployment_cache = {}
    c._list_cache = {}
    c._retry_backoff = (0, 0)
    c.get = make_fake_get(calls)
    c.prometheus = FakePrometheus()
    return c, calls


def make_client_for_retry(fetch_fn):
    """A Client with only `_fetch` (the single-attempt HTTP call) replaced,
    unlike make_client above which replaces `get` wholesale -- so `get`'s
    real retry-on-429 loop actually runs against `fetch_fn`. _retry_backoff
    is (0, 0): same retry COUNT (two) as production's (0.5, 1.0), just
    without the real sleep, so this test stays fast and deterministic."""
    c = client_mod.Client.__new__(client_mod.Client)
    c.unverifiable = []
    c._discovery_cache = {}
    c._deployment_cache = {}
    c._list_cache = {}
    c._retry_backoff = (0, 0)
    c._fetch = fetch_fn
    return c


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
    client, calls = make_client()

    fin_problems = finalizers.check(client, NOW)
    flux_problems = flux.check(client, NOW)
    cp_problems = crossplane.check(client, NOW)
    alert_problems = alerts.check(client, NOW)
    node_problems = nodes.check(client, NOW)
    stale_problems = stale.check(client, NOW)

    all_problems = (
        fin_problems + flux_problems + cp_problems + alert_problems + node_problems + stale_problems
    )
    print("problems found: fin={} flux={} crossplane={} alerts={} nodes={} stale={}".format(
        len(fin_problems), len(flux_problems), len(cp_problems),
        len(alert_problems), len(node_problems), len(stale_problems),
    ))
    print("distinct GET paths requested: {}".format(len(calls)))

    stuck = find_problem(fin_problems, "stuck-pg")
    check(
        "the widened scan finds a stuck postgresql.cnpg.io Cluster through the "
        "real Client end-to-end (discovery -> list -> orphaned-finalizer problem)",
        stuck is not None
        and stuck["kind"] == "Cluster"
        and stuck["category"] == "orphaned-finalizer",
        "found={}".format(stuck),
    )

    check(
        "a resource with no \"list\" verb (postgresql.cnpg.io Backup) is never "
        "requested at all",
        not any("backups" in path for path in calls),
        "calls={}".format(sorted(calls)),
    )

    check(
        "alerts.check ran against the shared FakePrometheus exactly once and "
        "reported zero problems (empty canned alert list)",
        alert_problems == [] and client.prometheus.alert_calls == 1,
        "alert_problems={} alert_calls={}".format(alert_problems, client.prometheus.alert_calls),
    )
    check(
        "nodes.check never queried Prometheus at all -- no node in this fake "
        "cluster is cordoned",
        client.prometheus.query_calls == 0,
        "query_calls={}".format(client.prometheus.query_calls),
    )
    check(
        "stale.check and nodes.check ran over the fixture Node without "
        "flagging it (Ready=True, unschedulable=False)",
        find_problem(node_problems, "k-fixture-healthy") is None
        and find_problem(stale_problems, "k-fixture-healthy") is None,
        "node_problems={} stale_problems={}".format(node_problems, stale_problems),
    )

    shared_lists = [
        "/apis/apiextensions.k8s.io/v1/customresourcedefinitions",
        "/apis/kustomize.toolkit.fluxcd.io/v1/kustomizations",
        "/apis/helm.toolkit.fluxcd.io/v2/helmreleases",
        "/apis/source.toolkit.fluxcd.io/v1/gitrepositories",
        "/apis/source.toolkit.fluxcd.io/v1/helmrepositories",
        "/apis/source.toolkit.fluxcd.io/v1/ocirepositories",
        "/apis/source.toolkit.fluxcd.io/v1/buckets",
        "/apis/pkg.crossplane.io/v1/providers",
        "/apis/pkg.crossplane.io/v1/providerrevisions",
        "/apis/apps/v1/deployments",
        "/api/v1/nodes",
    ]
    for path in shared_lists:
        check(
            "{} is listed at most once across every one of the six check "
            "modules that share this Client".format(path),
            calls.get(path) == 1,
            "calls[{}]={}".format(path, calls.get(path)),
        )

    check(
        "the widened scan's own new list (postgresql.cnpg.io Clusters) is "
        "listed exactly once",
        calls.get("/apis/postgresql.cnpg.io/v1/clusters") == 1,
        "calls={}".format(calls.get("/apis/postgresql.cnpg.io/v1/clusters")),
    )

    new_kind_lists = [
        "/apis/apps/v1/namespaces/kured/daemonsets",
        "/apis/discovery.k8s.io/v1/endpointslices",
        "/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations",
        "/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations",
    ]
    for path in new_kind_lists:
        check(
            "{} (a new kind added for alerts/nodes/stale) is listed exactly once".format(path),
            calls.get(path) == 1,
            "calls={}".format(calls.get(path)),
        )

    check(
        "discovery for a group multiple modules touch (pkg.crossplane.io) "
        "happens once each for the group doc and the version doc",
        calls.get("/apis/pkg.crossplane.io") == 1 and calls.get("/apis/pkg.crossplane.io/v1") == 1,
        "calls={}".format({
            k: v for k, v in calls.items() if k.startswith("/apis/pkg.crossplane.io")
        }),
    )

    check(
        "no path was requested more than once at all -- the strongest form "
        "of the \"at most once per run\" guarantee",
        all(n == 1 for n in calls.values()),
        "paths requested more than once: {}".format(
            {k: v for k, v in calls.items() if v != 1}
        ),
    )

    check("no call failed / landed in unverifiable", client.unverifiable == [], "unverifiable={}".format(client.unverifiable))

    print()
    run_retry()

    if FAILURES:
        print("FAILED: {}".format(", ".join(FAILURES)))
        return 1
    print("all checks passed")
    return 0


# --- scenario: 429 (TooManyRequests) retry in Client.get/get_safe -------


def run_retry():
    print("-- scenario: 429 (TooManyRequests) retry in Client.get/get_safe --")

    # Succeeds on the third attempt (two retries): "storage is
    # (re)initializing" -- e.g. right after an apiserver restart while its
    # watch cache warms up -- is transient, so a list that clears within
    # two retries must succeed and never land in unverifiable at all.
    attempts = {"n": 0}

    def flaky_then_ok(path, params=None):
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise client_mod.ApiError("GET", path, 429, "storage is (re)initializing")
        return {"items": []}

    client = make_client_for_retry(flaky_then_ok)
    result = client.get_safe("/api/v1/pods", "list pods (cluster-wide)")
    check(
        "a 429 that clears within two retries succeeds (three attempts "
        "total) and is never recorded to unverifiable",
        result == {"items": []} and attempts["n"] == 3 and client.unverifiable == [],
        "attempts={} result={} unverifiable={}".format(attempts["n"], result, client.unverifiable),
    )

    # Exhausts both retries (three total attempts) and still fails -- must
    # still land in unverifiable, same as any other denied call, just after
    # retrying rather than failing immediately.
    attempts2 = {"n": 0}

    def always_429(path, params=None):
        attempts2["n"] += 1
        raise client_mod.ApiError("GET", path, 429, "storage is (re)initializing")

    client2 = make_client_for_retry(always_429)
    result2 = client2.get_safe("/api/v1/pods", "list pods (cluster-wide)")
    check(
        "a 429 that never clears is retried twice (three attempts total) "
        "and then lands in unverifiable via get_safe, same as any other "
        "failed call",
        result2 is None
        and attempts2["n"] == 3
        and len(client2.unverifiable) == 1
        and "pods" in client2.unverifiable[0]["attempted"]
        and "storage is (re)initializing" in client2.unverifiable[0]["detail"],
        "attempts={} unverifiable={}".format(attempts2["n"], client2.unverifiable),
    )

    # A non-429 failure (e.g. 403) is not retried at all -- exactly one
    # attempt, so a genuinely denied call isn't slowed down for nothing.
    attempts3 = {"n": 0}

    def always_403(path, params=None):
        attempts3["n"] += 1
        raise client_mod.ApiError("GET", path, 403, "Forbidden")

    client3 = make_client_for_retry(always_403)
    result3 = client3.get_safe("/api/v1/pods", "list pods (cluster-wide)")
    check(
        "a non-429 failure (403) is not retried at all -- exactly one attempt",
        result3 is None and attempts3["n"] == 1,
        "attempts={}".format(attempts3["n"]),
    )

    print()


if __name__ == "__main__":
    try:
        sys.exit(run())
    except Exception:
        traceback.print_exc()
        sys.exit(1)
