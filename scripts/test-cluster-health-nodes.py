#!/usr/bin/env python3
"""Local test for platform/cluster-health's nodes.py, no cluster access
required. Same approach as the other test-cluster-health-*.py scripts (see
test-cluster-health-stale.py's docstring): nodes.check() runs against a
FakeClient loaded with fixture Node/DaemonSet objects, and a FakePrometheus
(injected on client.prometheus, same contract prometheus.for_client's own
docstring describes) that records which PromQL expressions it was asked and
answers per lookback window.

Scenarios:

1. run_cordon_freeze_replay() -- a replay of the 2026-09-27 kured freeze:
   node k-95509ca9 unschedulable, Prometheus showing it cordoned through the
   12h window but not the 1d window, and a kured lock naming it created 17h
   ago with TTL 1800000000000 (30m). Must flag node-cordoned ("at least
   12h", source prometheus, since = the lock's created time) and
   kured-lock-stale (17h held against a 30m TTL).
2. run_cordoned_briefly_not_flagged() -- a node cordoned 10 minutes (absent
   from the 30m window, lock only 10m old) is flagged by neither check.
3. run_no_query_when_not_cordoned() -- no node cordoned at all -> zero
   Prometheus queries issued.
4. run_prometheus_unreadable_no_lock() -- Prometheus's threshold-window
   query returns None (unreadable) and no lock names the node -> a warning,
   source "unknown", with null duration/since.
5. run_multi_lock_form() -- kured's multi-lock annotation form
   ({"maxOwners": N, "locks": [...]})  parses each entry independently.
6. run_unparseable_annotation() -- an annotation that isn't valid JSON lands
   in client.unverifiable rather than being silently ignored.
7. run_kured_lock_ttl_zero_fallback() -- TTL 0 (or absent) falls back to
   KURED_LOCK_MAX_MINUTES (default 30m) instead of never expiring.
8. run_node_memory() -- the live values from the parent Effort's request
   (k-e7488b70 61%, k-0ad0ff18 and k-95509ca9 both ~94%) are not flagged;
   synthetic nodes at 45%/40% usable fraction, expressed in Mi, Gi, decimal
   G and exponent-form quantities, are flagged; plain-byte and
   missing/unparseable quantities are handled without crashing.
9. run_quantity_parsing_unit() -- a direct, fine-grained check of
   nodes._parse_quantity across binary (Ki/Mi/Gi), decimal SI, plain-byte,
   exponent and milli forms.

    scripts/test-cluster-health-nodes.py
"""

import json
import os
import re
import sys
import traceback
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "platform", "cluster-health"))

import nodes

NOW = datetime.now(timezone.utc).replace(microsecond=0)


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def ago_minutes(minutes):
    return iso(NOW - timedelta(minutes=minutes))


def ago_hours(hours):
    return iso(NOW - timedelta(hours=hours))


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




class FakePrometheus:
    """Stand-in for prometheus.Prometheus: only the one method nodes.py
    calls (.query(expr)). Answers are keyed by the window literal inside
    min_over_time(kube_node_spec_unschedulable[<window>]) -- e.g. "30m",
    "12h", "1d" -- so a test can answer per ladder rung directly instead of
    hand-building the whole expr string. A window missing from `answers`
    returns [] (matching "no cordoned nodes", which naturally stops the
    ladder); a window explicitly mapped to None simulates an unreadable
    Prometheus, exactly like prometheus.Prometheus.query's own contract."""

    _WINDOW_RE = re.compile(r"\[(?P<window>[^\]]+)\]")

    def __init__(self, answers):
        self._answers = answers
        self.calls = []

    def query(self, expr):
        self.calls.append(expr)
        match = self._WINDOW_RE.search(expr)
        window = match.group("window") if match else None
        if window not in self._answers:
            return []
        return self._answers[window]


def _vec(*node_names):
    return [{"metric": {"node": name}, "value": [0, "1"]} for name in node_names]


class FakeClient:
    """A minimal stand-in for client.Client carrying only what nodes.py
    calls: list_resource and .unverifiable, plus a pre-set .prometheus (the
    test's FakePrometheus, injected the same way prometheus.for_client's own
    docstring says a real caller would)."""

    def __init__(self, prom=None):
        self.unverifiable = []
        self._resources = {}
        self.prometheus = prom

    def set_resource(self, group, resource, namespace, items):
        self._resources[(group, resource, namespace)] = items

    def list_resource(self, group, resource, namespace=None):
        return self._resources.get((group, resource, namespace), [])


def _node(name, unschedulable=False, capacity_memory=None, allocatable_memory=None):
    status = {}
    if capacity_memory is not None:
        status["capacity"] = {"memory": capacity_memory}
    if allocatable_memory is not None:
        status["allocatable"] = {"memory": allocatable_memory}
    return {
        "apiVersion": "v1",
        "kind": "Node",
        "metadata": {"name": name},
        "spec": {"unschedulable": unschedulable},
        "status": status,
    }


def _daemonset(name="kured", namespace="kured", lock_annotation_value=None):
    annotations = {}
    if lock_annotation_value is not None:
        annotations[nodes.DEFAULT_KURED_LOCK_ANNOTATION] = lock_annotation_value
    return {
        "apiVersion": "apps/v1",
        "kind": "DaemonSet",
        "metadata": {"name": name, "namespace": namespace, "annotations": annotations},
    }


def _single_lock(node_id, created, ttl_ns=None):
    payload = {"nodeID": node_id, "metadata": {"unschedulable": True}, "created": created}
    if ttl_ns is not None:
        payload["TTL"] = ttl_ns
    return json.dumps(payload)


def _multi_lock(entries):
    locks = []
    for node_id, created, ttl_ns in entries:
        entry = {"nodeID": node_id, "metadata": {"unschedulable": True}, "created": created}
        if ttl_ns is not None:
            entry["TTL"] = ttl_ns
        locks.append(entry)
    return json.dumps({"maxOwners": len(locks), "locks": locks})




def run_cordon_freeze_replay():
    print("-- scenario: 2026-09-27 freeze replay --")

    lock_created = ago_hours(17)
    prom = FakePrometheus(
        {
            "30m": _vec("k-95509ca9"),
            "1h": _vec("k-95509ca9"),
            "2h": _vec("k-95509ca9"),
            "6h": _vec("k-95509ca9"),
            "12h": _vec("k-95509ca9"),
            "1d": [],
        }
    )
    client = FakeClient(prom)
    client.set_resource("", "nodes", None, [_node("k-95509ca9", unschedulable=True)])
    client.set_resource(
        "apps",
        "daemonsets",
        "kured",
        [_daemonset(lock_annotation_value=_single_lock("k-95509ca9", lock_created, ttl_ns=1800000000000))],
    )

    problems = nodes.check(client, NOW)

    cordoned = find_problem(problems, "k-95509ca9", category="node-cordoned")
    check(
        "the frozen node is flagged node-cordoned, critical, 'at least 12h', via prometheus",
        cordoned is not None
        and cordoned["severity"] == "critical"
        and "at least 12h" in cordoned["detail"]
        and cordoned["source"] == "prometheus"
        and cordoned["since"] == lock_created
        and cordoned["cordoned_for_at_least_seconds"] == 12 * 3600,
        "found={}".format(cordoned),
    )
    check(
        "its detail also names the kured lock's since",
        cordoned is not None and lock_created in cordoned["detail"],
        "detail={}".format(cordoned["detail"] if cordoned else None),
    )

    lock_stale = find_problem(problems, "kured", category="kured-lock-stale")
    check(
        "the kured lock held 17h against a 30m TTL is flagged kured-lock-stale, critical",
        lock_stale is not None
        and lock_stale["severity"] == "critical"
        and lock_stale["namespace"] == "kured"
        and lock_stale["node"] == "k-95509ca9",
        "found={}".format(lock_stale),
    )

    print()




def run_cordoned_briefly_not_flagged():
    print("-- scenario: cordoned 10 minutes -- not flagged by either check --")

    prom = FakePrometheus({"30m": []})
    client = FakeClient(prom)
    client.set_resource("", "nodes", None, [_node("k-fresh-cordon", unschedulable=True)])
    client.set_resource(
        "apps",
        "daemonsets",
        "kured",
        [_daemonset(lock_annotation_value=_single_lock("k-fresh-cordon", ago_minutes(10), ttl_ns=1800000000000))],
    )

    problems = nodes.check(client, NOW)

    check(
        "not flagged node-cordoned",
        find_problem(problems, "k-fresh-cordon", category="node-cordoned") is None,
        "problems={}".format(problems),
    )
    check(
        "not flagged kured-lock-stale",
        count_category(problems, "kured-lock-stale") == 0,
        "problems={}".format(problems),
    )
    check("only one Prometheus query was needed", len(prom.calls) == 1, "calls={}".format(prom.calls))

    print()




def run_no_query_when_not_cordoned():
    print("-- scenario: no cordoned node -- no Prometheus query is made --")

    prom = FakePrometheus({})
    client = FakeClient(prom)
    client.set_resource("", "nodes", None, [_node("k-healthy", unschedulable=False)])

    problems = nodes.check(client, NOW)

    check("no node-cordoned problem", count_category(problems, "node-cordoned") == 0, "problems={}".format(problems))
    check("zero Prometheus queries issued", prom.calls == [], "calls={}".format(prom.calls))

    print()




def run_prometheus_unreadable_no_lock():
    print("-- scenario: Prometheus unreadable, no kured lock -- warning --")

    prom = FakePrometheus({"30m": None})
    client = FakeClient(prom)
    client.set_resource("", "nodes", None, [_node("k-unreadable-prom", unschedulable=True)])

    problems = nodes.check(client, NOW)

    warned = find_problem(problems, "k-unreadable-prom", category="node-cordoned")
    check(
        "flagged node-cordoned as a warning, source unknown, null duration/since",
        warned is not None
        and warned["severity"] == "warning"
        and warned["source"] == "unknown"
        and warned["cordoned_for_at_least_seconds"] is None
        and warned["since"] is None,
        "found={}".format(warned),
    )

    print()




def run_multi_lock_form():
    print("-- scenario: multi-lock annotation form (concurrency > 1) --")

    client = FakeClient()
    client.set_resource(
        "apps",
        "daemonsets",
        "kured",
        [
            _daemonset(
                lock_annotation_value=_multi_lock(
                    [
                        ("node-a", ago_hours(2), 1800000000000),
                        ("node-b", ago_minutes(5), 1800000000000),
                    ]
                )
            )
        ],
    )

    problems = nodes.check(client, NOW)

    check(
        "exactly one kured-lock-stale problem from the two-entry multi-lock form",
        count_category(problems, "kured-lock-stale") == 1,
        "problems={}".format([p for p in problems if p["category"] == "kured-lock-stale"]),
    )
    stale_entries = [p for p in problems if p["category"] == "kured-lock-stale"]
    check(
        "the stale entry names node-a, not node-b",
        len(stale_entries) == 1 and stale_entries[0]["node"] == "node-a",
        "found={}".format(stale_entries),
    )

    print()




def run_unparseable_annotation():
    print("-- scenario: an annotation that is not valid JSON --")

    client = FakeClient()
    client.set_resource(
        "apps", "daemonsets", "kured", [_daemonset(lock_annotation_value="not-json-at-all{{{")]
    )

    problems = nodes.check(client, NOW)

    check(
        "no kured-lock-stale problem from unparseable JSON",
        count_category(problems, "kured-lock-stale") == 0,
        "problems={}".format(problems),
    )
    check(
        "the parse failure lands in client.unverifiable rather than being silently ignored",
        any("parse kured lock annotation" in e.get("attempted", "") for e in client.unverifiable),
        "unverifiable={}".format(client.unverifiable),
    )

    print()




def run_kured_lock_ttl_zero_fallback():
    print("-- scenario: TTL 0/absent falls back to KURED_LOCK_MAX_MINUTES (30m) --")

    client = FakeClient()
    client.set_resource(
        "apps",
        "daemonsets",
        "kured",
        [
            _daemonset(
                lock_annotation_value=_multi_lock(
                    [
                        ("node-ttl-zero-old", ago_minutes(40), 0),
                        ("node-ttl-zero-fresh", ago_minutes(20), 0),
                    ]
                )
            )
        ],
    )

    problems = nodes.check(client, NOW)
    stale_entries = {p["node"]: p for p in problems if p["category"] == "kured-lock-stale"}

    check(
        "TTL=0 held 40m (past the 30m fallback) is flagged",
        "node-ttl-zero-old" in stale_entries,
        "stale_entries={}".format(stale_entries),
    )
    check(
        "TTL=0 held 20m (within the 30m fallback) is not flagged",
        "node-ttl-zero-fresh" not in stale_entries,
        "stale_entries={}".format(stale_entries),
    )

    print()




def run_node_memory():
    print("-- scenario: node-memory-low --")

    client = FakeClient()
    nodes_list = [
        _node("k-e7488b70", capacity_memory="8117184Ki", allocatable_memory="4971456Ki"),
        _node("k-0ad0ff18", capacity_memory="32657820Ki", allocatable_memory="30560668Ki"),
        _node("k-95509ca9-mem", capacity_memory="32851516Ki", allocatable_memory="30754364Ki"),
        _node("k-mem-mi-45pct", capacity_memory="10000Mi", allocatable_memory="4500Mi"),
        _node("k-mem-gi-45pct", capacity_memory="10000Gi", allocatable_memory="4500Gi"),
        _node("k-mem-decimal-g-40pct", capacity_memory="10G", allocatable_memory="4G"),
        _node("k-mem-plain-bytes-75pct", capacity_memory="10000000000", allocatable_memory="7500000000"),
        _node("k-mem-exponent-40pct", capacity_memory="1e10", allocatable_memory="4e9"),
        _node("k-mem-missing", capacity_memory=None, allocatable_memory="4G"),
        _node("k-mem-garbage", capacity_memory="not-a-quantity", allocatable_memory="4G"),
    ]
    client.set_resource("", "nodes", None, nodes_list)

    problems = nodes.check(client, NOW)
    mem_problems = {p["name"]: p for p in problems if p["category"] == "node-memory-low"}

    print("node-memory-low problems found: {}".format(sorted(mem_problems)))

    for name in ("k-e7488b70", "k-0ad0ff18", "k-95509ca9-mem", "k-mem-plain-bytes-75pct"):
        check("{} is not flagged".format(name), name not in mem_problems, "mem_problems={}".format(mem_problems))

    for name, expected_fraction in (
        ("k-mem-mi-45pct", 0.45),
        ("k-mem-gi-45pct", 0.45),
        ("k-mem-decimal-g-40pct", 0.4),
        ("k-mem-exponent-40pct", 0.4),
    ):
        problem = mem_problems.get(name)
        check(
            "{} is flagged warning with usable_fraction {}".format(name, expected_fraction),
            problem is not None
            and problem["severity"] == "warning"
            and abs(problem["usable_fraction"] - expected_fraction) < 1e-9,
            "found={}".format(problem),
        )

    for name in ("k-mem-missing", "k-mem-garbage"):
        check(
            "{} (missing/unparseable quantity) is skipped, not flagged".format(name),
            name not in mem_problems,
            "mem_problems={}".format(mem_problems),
        )

    check(
        "exactly 4 node-memory-low problems in this fixture",
        len(mem_problems) == 4,
        "mem_problems={}".format(mem_problems),
    )

    print()




def run_quantity_parsing_unit():
    print("-- scenario: nodes._parse_quantity unit coverage --")

    cases = [
        ("8Ki", 8 * 1024),
        ("8Mi", 8 * 1024 ** 2),
        ("8Gi", 8 * 1024 ** 3),
        ("8k", 8000.0),
        ("8M", 8e6),
        ("8G", 8e9),
        ("8", 8.0),
        ("8000000000", 8e9),
        ("8e9", 8e9),
        ("1.5e3", 1500.0),
        ("8000m", 8.0),
        (None, None),
        ("", None),
        ("garbage", None),
    ]
    for raw, expected in cases:
        got = nodes._parse_quantity(raw)
        if expected is None:
            check("_parse_quantity({!r}) is None".format(raw), got is None, "got={}".format(got))
        else:
            check(
                "_parse_quantity({!r}) == {}".format(raw, expected),
                got is not None and abs(got - expected) < 1e-6,
                "got={}".format(got),
            )

    print()


def run():
    run_cordon_freeze_replay()
    run_cordoned_briefly_not_flagged()
    run_no_query_when_not_cordoned()
    run_prometheus_unreadable_no_lock()
    run_multi_lock_form()
    run_unparseable_annotation()
    run_kured_lock_ttl_zero_fallback()
    run_node_memory()
    run_quantity_parsing_unit()

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
