"""Prometheus alerting-rules check.

Same interface as finalizers.check/flux.check/crossplane.check so server.py
can sum this module's problems in too: `check(client, now) -> list` of
problem dicts shaped like finalizers.CATEGORY's ({category, severity, kind,
apiVersion, namespace, name, detail, ...}). Unlike the other three, this one
reads Prometheus (prometheus.for_client(client).alerts()) rather than the
Kubernetes API -- a firing alert is itself the signal, no object lookup
needed -- so `kind`/`apiVersion` are synthetic ("Alert" / "") rather than a
real Kubernetes GVK.

Two categories:

* "prometheus-alert" -- one problem per alert currently state=="firing",
  excluding IGNORED_ALERTS (Watchdog, InfoInhibitor -- Alertmanager/
  Prometheus meta-alerts kept firing by design, always on, never a real
  problem). A "pending" alert hasn't crossed its rule's `for:` duration yet
  and is not reported. Severity comes from the alert's own `severity` label
  (critical -> critical, warning -> warning); anything else -- info, none,
  or no severity label at all -- maps to "info" rather than being dropped,
  so an alert this check doesn't specifically know about still surfaces,
  just not urgently.
* "reboot-gate-closed" -- kured will not reboot a node while the alert named
  by REBOOT_GATE_ALERT (default "RebootGateClosed") is firing (by design:
  that alert fires while any node is not Ready or any severity=critical
  alert is firing, which is exactly when a reboot would be unsafe). Left
  firing for a long time, that is not a problem in itself but a silent one:
  node patching has stopped and nothing says so. If that alert has been
  firing longer than REBOOT_GATE_MAX_HOURS (default 24) hours, this reports
  one extra "critical" problem naming how long reboots have been blocked and
  which other critical alerts are firing alongside it (the likely cause, if
  any). The gate alert also appears under "prometheus-alert" like any other
  firing alert while it fires -- that duplication is intended, not a bug.

If Prometheus itself cannot be reached, prometheus.alerts() has already
recorded that failure to client.unverifiable and returns None; this check
then reports zero problems rather than guessing.
"""

import os
import re
from datetime import datetime, timedelta, timezone

import prometheus

CATEGORY_ALERT = "prometheus-alert"
CATEGORY_REBOOT_GATE = "reboot-gate-closed"

IGNORED_ALERTS = {"Watchdog", "InfoInhibitor"}

_SEVERITY_MAP = {"critical": "critical", "warning": "warning"}

_TS_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
    r"(?:\.(?P<frac>\d+))?"
    r"(?P<tz>Z|[+-]\d{2}:\d{2})?$"
)


def _reboot_gate_alert_name():
    return os.environ.get("REBOOT_GATE_ALERT", "RebootGateClosed")


def _reboot_gate_max_hours():
    try:
        return float(os.environ.get("REBOOT_GATE_MAX_HOURS", "24"))
    except ValueError:
        return 24.0


def _parse_ts(raw):
    if not raw:
        return None
    match = _TS_RE.match(raw)
    if not match:
        return None
    try:
        dt = datetime.strptime(match.group("date"), "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None
    frac = match.group("frac")
    if frac:
        dt = dt.replace(microsecond=int((frac + "000000")[:6]))
    tz = match.group("tz")
    if tz is None or tz == "Z":
        return dt.replace(tzinfo=timezone.utc)
    sign = 1 if tz[0] == "+" else -1
    offset = timedelta(hours=int(tz[1:3]), minutes=int(tz[4:6]))
    return (dt - sign * offset).replace(tzinfo=timezone.utc)


def _format_ts(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _format_duration(seconds):
    seconds = int(seconds)
    hours, rem = divmod(seconds, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return "{}h{}m".format(hours, minutes)
    if minutes:
        return "{}m{}s".format(minutes, secs)
    return "{}s".format(secs)


def _alert_name(alert):
    return (alert.get("labels") or {}).get("alertname", "<unknown>")


def _severity_for(alert):
    label = (alert.get("labels") or {}).get("severity")
    return _SEVERITY_MAP.get(label, "info")


def _summary(alert):
    annotations = alert.get("annotations") or {}
    return annotations.get("summary") or annotations.get("description") or annotations.get("message") or ""


def _alert_problem(alert, since_dt, firing_for_seconds):
    labels = alert.get("labels") or {}
    name = _alert_name(alert)
    since = _format_ts(since_dt)
    return {
        "category": CATEGORY_ALERT,
        "severity": _severity_for(alert),
        "kind": "Alert",
        "apiVersion": "",
        "namespace": labels.get("namespace") or "",
        "name": name,
        "detail": "{} firing since {} ({}): {}".format(
            name, since, _format_duration(firing_for_seconds), _summary(alert)
        ),
        "since": since,
        "firing_for_seconds": int(firing_for_seconds),
        "labels": labels,
    }


def _reboot_gate_problem(gate_alert, since_dt, age_seconds, other_critical):
    labels = gate_alert.get("labels") or {}
    name = _alert_name(gate_alert)
    since = _format_ts(since_dt)
    detail = (
        "{} has been firing since {} ({}), so node reboots have been blocked "
        "and have silently stopped".format(name, since, _format_duration(age_seconds))
    )
    if other_critical:
        detail += "; other firing critical alerts (likely cause): {}".format(
            ", ".join(sorted(other_critical))
        )
    return {
        "category": CATEGORY_REBOOT_GATE,
        "severity": "critical",
        "kind": "Alert",
        "apiVersion": "",
        "namespace": labels.get("namespace") or "",
        "name": name,
        "detail": detail,
    }


def check(client, now):
    alerts = prometheus.for_client(client).alerts()
    if alerts is None:
        return []

    gate_name = _reboot_gate_alert_name()
    max_age_seconds = _reboot_gate_max_hours() * 3600

    problems = []
    other_critical = set()
    gate_alert = None
    gate_since = None
    gate_age_seconds = None

    for alert in alerts:
        if alert.get("state") != "firing":
            continue

        name = _alert_name(alert)
        since_dt = _parse_ts(alert.get("activeAt"))
        firing_for_seconds = (now - since_dt).total_seconds() if since_dt is not None else 0.0

        if name not in IGNORED_ALERTS:
            problems.append(_alert_problem(alert, since_dt or now, firing_for_seconds))

        if name == gate_name:
            gate_alert = alert
            gate_since = since_dt
            gate_age_seconds = firing_for_seconds
        elif _severity_for(alert) == "critical":
            other_critical.add(name)

    if (
        gate_alert is not None
        and gate_since is not None
        and gate_age_seconds is not None
        and gate_age_seconds >= max_age_seconds
    ):
        problems.append(_reboot_gate_problem(gate_alert, gate_since, gate_age_seconds, other_critical))

    return problems
