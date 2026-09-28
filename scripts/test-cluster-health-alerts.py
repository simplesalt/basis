#!/usr/bin/env python3
"""Local test for platform/cluster-health's prometheus.py and alerts.py, no
cluster access required for most scenarios (one optional scenario at the end
does reach the live Prometheus from this environment, read-only, and never
fails the suite on its own).

Three groups of scenarios, mirroring the other test-cluster-health-*.py
scripts' shape (FakeClient/fixtures, `check()` asserting a label and
tallying FAILURES, no pytest):

1. run_prometheus_class() / run_for_client() -- exercise the real
   prometheus.Prometheus class with only its one HTTP attempt (_fetch)
   overridden, same pattern as test-cluster-health-client-cache.py does for
   client.Client: a success body is parsed, an HTTP error and a
   status=="error" body are each recorded exactly once to `unverifiable`
   and return None, and a second call (alerts() with no args, or query()
   with the same expr) is served from cache -- no second request. Also
   covers for_client()'s "reuse what's already on client.prometheus, else
   build and stash one" contract.
2. run_ignored_and_pending() / run_severity_mapping() / run_reboot_gate() --
   exercise alerts.check() against a FakePrometheus (only the one method
   alerts.py calls, .alerts()) loaded with canned alert lists: Watchdog/
   InfoInhibitor and any "pending" alert are excluded; a firing alert is
   reported with its severity label mapped (critical/warning) or "info" for
   anything else (including no severity label at all); fractional-second
   and numeric-offset activeAt timestamps both parse to the same normalized
   "since"; RebootGateClosed firing past REBOOT_GATE_MAX_HOURS is flagged
   "reboot-gate-closed" (naming other firing critical alerts as the likely
   cause) while still also appearing under "prometheus-alert" -- that
   duplication is intended -- and firing under the threshold is not flagged
   reboot-gate-closed but still appears under prometheus-alert.
3. run_prometheus_unreachable() -- a real Prometheus instance whose _fetch
   always raises: alerts.check() must report zero problems and the failure
   must land exactly once in client.unverifiable (never guessed at, never
   double-recorded).

run_live_smoke() at the end is the Request's optional read-only smoke test:
alerts.check() against the real, live Prometheus (curl reachable from this
environment), with a minimal stand-in client. It only prints what comes
back and never contributes to FAILURES -- this environment's network access
is not something the suite's pass/fail should depend on.

    scripts/test-cluster-health-alerts.py
"""

import os
import sys
import traceback
import urllib.error
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "platform", "cluster-health"))

import alerts
import prometheus

NOW = datetime.now(timezone.utc).replace(microsecond=0)


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


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




def _alert(alertname, state="firing", severity="warning", namespace=None, active_at=None, summary=None):
    """severity=None omits the label entirely (simulating an alert with no
    severity label at all); severity="none" sets it explicitly to the
    string Alertmanager gives Watchdog/InfoInhibitor -- both must map to
    "info", exercised separately below."""
    labels = {"alertname": alertname}
    if severity is not None:
        labels["severity"] = severity
    if namespace:
        labels["namespace"] = namespace
    annotations = {}
    if summary:
        annotations["summary"] = summary
    return {
        "labels": labels,
        "annotations": annotations,
        "state": state,
        "activeAt": active_at if active_at is not None else ago_hours(0),
        "value": "1",
    }


class FakePrometheus:
    """Stand-in for prometheus.Prometheus: only the one method alerts.py
    calls (.alerts()), counting invocations the way the other tests' fakes
    count list_resource calls."""

    def __init__(self, alerts_list):
        self._alerts_list = alerts_list
        self.calls = 0

    def alerts(self):
        self.calls += 1
        return self._alerts_list


class FakeClient:
    """A minimal stand-in for client.Client carrying only what
    prometheus.for_client(client) and alerts.check(client, now) touch:
    .unverifiable and a pre-set .prometheus (the test's fake, injected the
    same way for_client's own docstring says a real caller would)."""

    def __init__(self, prom):
        self.unverifiable = []
        self.prometheus = prom




def run_prometheus_class():
    print("-- scenario: real Prometheus class, _fetch overridden --")

    unverifiable = []
    prom = prometheus.Prometheus("http://fake:9090", unverifiable)
    calls = {"n": 0}
    body = {
        "status": "success",
        "data": {
            "alerts": [
                {"labels": {"alertname": "X"}, "state": "firing", "activeAt": ago_hours(1)}
            ]
        },
    }

    def fetch_ok(path, params=None):
        calls["n"] += 1
        assert path == "/api/v1/alerts", "alerts() must GET /api/v1/alerts, got {!r}".format(path)
        return body

    prom._fetch = fetch_ok
    result = prom.alerts()
    check("a success body is parsed into data.alerts", result == body["data"]["alerts"], "result={}".format(result))
    check("no unverifiable entry on success", unverifiable == [], "unverifiable={}".format(unverifiable))

    result2 = prom.alerts()
    check(
        "a second alerts() call is served from cache -- no second request",
        calls["n"] == 1 and result2 == result,
        "calls={} result2={}".format(calls["n"], result2),
    )

    unverifiable_err = []
    prom_err = prometheus.Prometheus("http://fake:9090", unverifiable_err)

    def fetch_http_error(path, params=None):
        raise urllib.error.HTTPError(path, 500, "Internal Server Error", {}, None)

    prom_err._fetch = fetch_http_error
    result_err = prom_err.alerts()
    check("an HTTP error returns None", result_err is None)
    check(
        "...and is recorded exactly once in unverifiable",
        len(unverifiable_err) == 1,
        "unverifiable={}".format(unverifiable_err),
    )
    result_err2 = prom_err.alerts()
    check(
        "a cached failure is also served from cache -- still None, no new entry",
        result_err2 is None and len(unverifiable_err) == 1,
        "unverifiable={}".format(unverifiable_err),
    )

    unverifiable_status = []
    prom_status = prometheus.Prometheus("http://fake:9090", unverifiable_status)

    def fetch_status_error(path, params=None):
        return {"status": "error", "errorType": "bad_data", "error": "invalid parameter \"query\""}

    prom_status._fetch = fetch_status_error
    result_status = prom_status.query("up{bad")
    check("a status==\"error\" response returns None", result_status is None)
    check(
        "...and is recorded exactly once in unverifiable",
        len(unverifiable_status) == 1,
        "unverifiable={}".format(unverifiable_status),
    )

    unverifiable_q = []
    prom_q = prometheus.Prometheus("http://fake:9090", unverifiable_q)
    calls_q = {"n": 0}
    vector_result = [{"metric": {"__name__": "up"}, "value": [1758888000, "1"]}]

    def fetch_query_ok(path, params=None):
        calls_q["n"] += 1
        assert path == "/api/v1/query"
        assert params == {"query": "up"}
        return {"status": "success", "data": {"resultType": "vector", "result": vector_result}}

    prom_q._fetch = fetch_query_ok
    res_q = prom_q.query("up")
    check("query() returns data.result for a vector resultType", res_q == vector_result, "res_q={}".format(res_q))
    res_q2 = prom_q.query("up")
    check(
        "a repeated query() with the same expr is cached -- no second request",
        calls_q["n"] == 1 and res_q2 == res_q,
        "calls={}".format(calls_q["n"]),
    )

    def fetch_query_ok2(path, params=None):
        calls_q["n"] += 1
        return {"status": "success", "data": {"resultType": "vector", "result": []}}

    prom_q._fetch = fetch_query_ok2
    res_q3 = prom_q.query("down")
    check(
        "a different expr is a cache miss and issues its own request",
        calls_q["n"] == 2 and res_q3 == [],
        "calls={} res_q3={}".format(calls_q["n"], res_q3),
    )

    unverifiable_bad_type = []
    prom_bad_type = prometheus.Prometheus("http://fake:9090", unverifiable_bad_type)
    prom_bad_type._fetch = lambda path, params=None: {
        "status": "success",
        "data": {"resultType": "matrix", "result": []},
    }
    res_bad = prom_bad_type.query("up[5m]")
    check("a non-vector resultType returns None", res_bad is None)
    check(
        "...and is recorded once in unverifiable",
        len(unverifiable_bad_type) == 1,
        "unverifiable={}".format(unverifiable_bad_type),
    )

    print()




def run_for_client():
    print("-- scenario: prometheus.for_client sharing/injection --")

    class DummyClient:
        def __init__(self):
            self.unverifiable = []

    c = DummyClient()
    p1 = prometheus.for_client(c)
    check(
        "for_client builds a Prometheus and stashes it on client.prometheus",
        isinstance(p1, prometheus.Prometheus) and c.prometheus is p1,
        "type={} client.prometheus is p1={}".format(type(p1), c.prometheus is p1),
    )
    p2 = prometheus.for_client(c)
    check("a second for_client(c) call returns the same instance", p2 is p1)

    class PreInjectedClient:
        def __init__(self):
            self.unverifiable = []
            self.prometheus = "sentinel-fake"

    c2 = PreInjectedClient()
    check(
        "for_client returns an already-set client.prometheus untouched (test injection)",
        prometheus.for_client(c2) == "sentinel-fake",
        "got={}".format(prometheus.for_client(c2)),
    )

    print()




def run_ignored_and_pending():
    print("-- scenario: Watchdog/InfoInhibitor and pending alerts excluded --")

    alerts_list = [
        _alert("Watchdog", severity="none", active_at=ago_hours(48)),
        _alert("InfoInhibitor", severity="none", active_at=ago_hours(48)),
        _alert("CPUThrottlingHigh", state="pending", severity="info", active_at=ago_hours(0.1)),
        _alert("KubeVersionMismatch", severity="warning", active_at=ago_hours(3), summary="kubelet version mismatch"),
    ]
    client = FakeClient(FakePrometheus(alerts_list))
    problems = alerts.check(client, NOW)

    check("Watchdog is excluded even though it is firing", find_problem(problems, "Watchdog") is None)
    check("InfoInhibitor is excluded even though it is firing", find_problem(problems, "InfoInhibitor") is None)
    check("a pending alert is excluded", find_problem(problems, "CPUThrottlingHigh") is None)

    kvm = find_problem(problems, "KubeVersionMismatch", category="prometheus-alert")
    check(
        "a firing, non-ignored alert is reported under prometheus-alert with mapped severity",
        kvm is not None and kvm["severity"] == "warning",
        "found={}".format(kvm),
    )
    check("exactly one problem in this fixture", len(problems) == 1, "problems={}".format(problems))

    print()




def run_severity_mapping():
    print("-- scenario: severity mapping and since/duration from activeAt --")

    critical_since = ago_hours(1)
    warning_since = ago_hours(2)
    frac_raw = "{}.910168494Z".format((NOW - timedelta(hours=5)).strftime("%Y-%m-%dT%H:%M:%S"))
    frac_since = ago_hours(5)
    offset_raw = "{}+00:00".format((NOW - timedelta(hours=2, minutes=30)).strftime("%Y-%m-%dT%H:%M:%S"))
    offset_since = ago_hours(2.5)

    alerts_list = [
        _alert("CriticalThing", severity="critical", namespace="ns1", active_at=critical_since, summary="bad news"),
        _alert("WarningThing", severity="warning", active_at=warning_since),
        _alert("NoSeverityLabelAtAll", severity=None, active_at=ago_hours(0.5)),
        _alert("ExplicitInfoSeverity", severity="info", active_at=ago_hours(0.5)),
        _alert("FractionalTimestamp", severity="warning", active_at=frac_raw),
        _alert("OffsetTimestamp", severity="warning", active_at=offset_raw),
    ]
    client = FakeClient(FakePrometheus(alerts_list))
    problems = alerts.check(client, NOW)

    crit = find_problem(problems, "CriticalThing")
    check(
        "severity label critical maps to problem severity critical, with namespace and since carried through",
        crit is not None
        and crit["severity"] == "critical"
        and crit["namespace"] == "ns1"
        and crit["since"] == critical_since
        and "bad news" in crit["detail"],
        "found={}".format(crit),
    )

    warn = find_problem(problems, "WarningThing")
    check(
        "severity label warning maps to problem severity warning, namespace defaults to \"\"",
        warn is not None and warn["severity"] == "warning" and warn["namespace"] == "" and warn["since"] == warning_since,
        "found={}".format(warn),
    )

    no_label = find_problem(problems, "NoSeverityLabelAtAll")
    check(
        "no severity label at all maps to \"info\", not dropped",
        no_label is not None and no_label["severity"] == "info",
        "found={}".format(no_label),
    )

    explicit_info = find_problem(problems, "ExplicitInfoSeverity")
    check(
        "an explicit severity=info label maps to \"info\"",
        explicit_info is not None and explicit_info["severity"] == "info",
        "found={}".format(explicit_info),
    )

    frac = find_problem(problems, "FractionalTimestamp")
    check(
        "a fractional-second activeAt (nine digits) parses and normalizes to the same "
        "whole-second \"since\" as its unfractional equivalent",
        frac is not None and frac["since"] == frac_since,
        "found={}".format(frac),
    )

    offset = find_problem(problems, "OffsetTimestamp")
    check(
        "a numeric-offset activeAt (+00:00) parses the same as a Z-suffixed one",
        offset is not None and offset["since"] == offset_since,
        "found={}".format(offset),
    )

    check(
        "every problem in this fixture is category prometheus-alert",
        count_category(problems, "prometheus-alert") == len(problems) == 6,
        "problems={}".format(problems),
    )

    print()




def run_reboot_gate():
    print("-- scenario: reboot-gate-closed --")

    alerts_25h = [
        _alert("RebootGateClosed", severity="warning", active_at=ago_hours(25)),
        _alert(
            "SomeNodeDown", severity="critical", namespace="kube-system",
            active_at=ago_hours(20), summary="node k-0ad0ff18 is NotReady",
        ),
    ]
    client = FakeClient(FakePrometheus(alerts_25h))
    problems = alerts.check(client, NOW)

    gate = find_problem(problems, "RebootGateClosed", category="reboot-gate-closed")
    check(
        "RebootGateClosed firing 25h is flagged reboot-gate-closed, critical",
        gate is not None and gate["severity"] == "critical",
        "found={}".format(gate),
    )
    check(
        "its detail names the other firing critical alert as the likely cause",
        gate is not None and "SomeNodeDown" in gate["detail"],
        "detail={}".format(gate["detail"] if gate else None),
    )
    check(
        "RebootGateClosed still also appears exactly once under prometheus-alert while it fires",
        count_category(
            [p for p in problems if p["name"] == "RebootGateClosed"], "prometheus-alert"
        ) == 1,
        "problems={}".format([p for p in problems if p["name"] == "RebootGateClosed"]),
    )

    alerts_2h = [_alert("RebootGateClosed", severity="warning", active_at=ago_hours(2))]
    client2 = FakeClient(FakePrometheus(alerts_2h))
    problems2 = alerts.check(client2, NOW)

    check(
        "RebootGateClosed firing only 2h is NOT flagged reboot-gate-closed",
        find_problem(problems2, "RebootGateClosed", category="reboot-gate-closed") is None,
        "problems={}".format(problems2),
    )
    check(
        "...but is still listed once as prometheus-alert",
        find_problem(problems2, "RebootGateClosed", category="prometheus-alert") is not None
        and len(problems2) == 1,
        "problems={}".format(problems2),
    )

    client3 = FakeClient(FakePrometheus([_alert("SomethingElse", severity="warning")]))
    problems3 = alerts.check(client3, NOW)
    check(
        "no RebootGateClosed alert present at all -- no reboot-gate-closed problem",
        find_problem(problems3, "RebootGateClosed") is None,
        "problems={}".format(problems3),
    )

    old_alert_env = os.environ.get("REBOOT_GATE_ALERT")
    old_hours_env = os.environ.get("REBOOT_GATE_MAX_HOURS")
    try:
        os.environ["REBOOT_GATE_ALERT"] = "CustomGateAlert"
        os.environ["REBOOT_GATE_MAX_HOURS"] = "1"
        client4 = FakeClient(FakePrometheus([_alert("CustomGateAlert", severity="warning", active_at=ago_hours(2))]))
        problems4 = alerts.check(client4, NOW)
        check(
            "REBOOT_GATE_ALERT/REBOOT_GATE_MAX_HOURS env overrides are honored",
            find_problem(problems4, "CustomGateAlert", category="reboot-gate-closed") is not None,
            "problems={}".format(problems4),
        )
    finally:
        if old_alert_env is None:
            os.environ.pop("REBOOT_GATE_ALERT", None)
        else:
            os.environ["REBOOT_GATE_ALERT"] = old_alert_env
        if old_hours_env is None:
            os.environ.pop("REBOOT_GATE_MAX_HOURS", None)
        else:
            os.environ["REBOOT_GATE_MAX_HOURS"] = old_hours_env

    print()




def run_prometheus_unreachable():
    print("-- scenario: Prometheus unreachable --")

    class MinimalClient:
        def __init__(self):
            self.unverifiable = []

    client = MinimalClient()
    prom = prometheus.Prometheus("http://unreachable.invalid:9090", client.unverifiable)

    def always_fails(path, params=None):
        raise urllib.error.URLError("Name or service not known")

    prom._fetch = always_fails
    client.prometheus = prom

    problems = alerts.check(client, NOW)
    check("Prometheus unreachable gives zero problems", problems == [], "problems={}".format(problems))
    check(
        "...and exactly one unverifiable entry",
        len(client.unverifiable) == 1,
        "unverifiable={}".format(client.unverifiable),
    )

    print()




def run_live_smoke():
    print("-- optional smoke test: alerts.check against the live Prometheus --")

    class LiveClient:
        def __init__(self):
            self.unverifiable = []

    client = LiveClient()
    try:
        problems = alerts.check(client, datetime.now(timezone.utc).replace(microsecond=0))
    except Exception:
        print("  (skipped -- exception talking to the live Prometheus)")
        traceback.print_exc()
        print()
        return

    print("  problems: {}".format(len(problems)))
    for p in problems:
        print(
            "    - [{}] {} {} :: {}".format(p["severity"], p["category"], p["name"], p["detail"])
        )
    print("  unverifiable: {}".format(client.unverifiable))
    print()


def run():
    run_prometheus_class()
    run_for_client()
    run_ignored_and_pending()
    run_severity_mapping()
    run_reboot_gate()
    run_prometheus_unreachable()
    run_live_smoke()

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
