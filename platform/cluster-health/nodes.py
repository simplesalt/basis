"""Node cordon / kured lock / node memory checks.

Same interface as finalizers.check/flux.check/crossplane.check/alerts.check/
stale.check so server.py can sum this module's problems in too:
`check(client, now) -> list` of problem dicts shaped like stale.py's
`_base_problem`'s ({category, severity, kind, apiVersion, namespace, name,
detail, ...}).

Why this module exists: on 2026-09-27 a kured drain held the cluster
cordoned for roughly 17 hours and nothing reported it. kured has since been
given a 15-minute drain limit and a reboot gate (see alerts.py's
"reboot-gate-closed"), but a cordon or a held lock can still stall silently
-- a Node's spec.unschedulable carries no timestamp of its own, and neither
does the unschedulable taint, so "how long has this been cordoned" has to be
reconstructed from somewhere else. Two independent sources, cross-checked:

* Prometheus's kube_node_spec_unschedulable{node="<name>"} (0/1 per node,
  scraped every 120s, retained 3d) -- `min_over_time(...[<window>]) == 1`
  over a fixed ladder of windows is a lower bound on how long a node has
  been continuously cordoned, capped by retention.
* kured's own lock, a JSON annotation
  (weave.works/kured-node-lock by default) on the kured DaemonSet, written
  right before kured cordons/drains a node and deleted after uncordon or a
  failed drain. Its `created` timestamp is authoritative for the one node it
  names, and reaches further back than Prometheus's 3-day retention if
  needed.

Three independent categories:

* "node-cordoned" -- a cordoned Node whose downtime, by either source,
  reaches CORDON_MAX_MINUTES (default 30).
* "kured-lock-stale" -- kured's own lock outliving its TTL (or
  KURED_LOCK_MAX_MINUTES when TTL is 0/absent) -- the lock itself stuck, a
  sign the drain it was guarding never finished and never cleaned up.
* "node-memory-low" -- a Node whose allocatable memory is too small a
  fraction of its capacity to be usable (the rest reserved for the system
  or eviction), independent of the cordon story above but sharing this
  module because it is also a Node-only, no-Prometheus-required-for-this-
  one signal.

Prometheus reads go through prometheus.for_client(client), the same shared,
per-/health-call instance alerts.py uses; a query failure is already
recorded on client.unverifiable by prometheus.py itself, so this module
reports None as "can't tell", never a guess. Kubernetes reads go through
client.list_resource, cached per (group, resource, namespace) for the
lifetime of one Client -- Nodes and the kured DaemonSet are each listed
once per check() call here.
"""

import json
import os
import re
from datetime import datetime, timedelta, timezone

import prometheus

CATEGORY_CORDONED = "node-cordoned"
CATEGORY_KURED_LOCK_STALE = "kured-lock-stale"
CATEGORY_MEMORY = "node-memory-low"

NODE_GROUP = ""
NODE_RESOURCE = "nodes"

DEFAULT_KURED_NAMESPACE = "kured"
DEFAULT_KURED_DAEMONSET = "kured"
DEFAULT_KURED_LOCK_ANNOTATION = "weave.works/kured-node-lock"

_FIXED_WINDOW_LADDER_MINUTES = (30, 60, 120, 360, 720, 1440, 2880, 4320)

_TS_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
    r"(?:\.(?P<frac>\d+))?"
    r"(?P<tz>Z|[+-]\d{2}:\d{2})?$"
)

_BINARY_QUANTITY_SUFFIXES = (
    ("Ei", 2 ** 60),
    ("Pi", 2 ** 50),
    ("Ti", 2 ** 40),
    ("Gi", 2 ** 30),
    ("Mi", 2 ** 20),
    ("Ki", 2 ** 10),
)
_DECIMAL_QUANTITY_SUFFIXES = (
    ("n", 1e-9),
    ("u", 1e-6),
    ("m", 1e-3),
    ("k", 1e3),
    ("M", 1e6),
    ("G", 1e9),
    ("T", 1e12),
    ("P", 1e15),
    ("E", 1e18),
)

_BYTE_UNITS = (("TiB", 2 ** 40), ("GiB", 2 ** 30), ("MiB", 2 ** 20), ("KiB", 2 ** 10))




def _cordon_max_minutes():
    try:
        return float(os.environ.get("CORDON_MAX_MINUTES", "30"))
    except ValueError:
        return 30.0


def _kured_namespace():
    return os.environ.get("KURED_NAMESPACE", DEFAULT_KURED_NAMESPACE)


def _kured_daemonset_name():
    return os.environ.get("KURED_DAEMONSET", DEFAULT_KURED_DAEMONSET)


def _kured_lock_annotation():
    return os.environ.get("KURED_LOCK_ANNOTATION", DEFAULT_KURED_LOCK_ANNOTATION)


def _kured_lock_max_minutes():
    try:
        return float(os.environ.get("KURED_LOCK_MAX_MINUTES", "30"))
    except ValueError:
        return 30.0


def _node_memory_min_usable_fraction():
    try:
        return float(os.environ.get("NODE_MEMORY_MIN_USABLE_FRACTION", "0.5"))
    except ValueError:
        return 0.5




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


def _prometheus_duration(minutes):
    """Render a whole number of minutes as a Prometheus duration literal,
    preferring the coarsest unit that divides evenly (720 -> "12h", 1440 ->
    "1d") the same way the module's fixed window ladder is described, and
    falling back to plain minutes for anything else (e.g. a
    CORDON_MAX_MINUTES override of 45 -> "45m")."""
    minutes = int(round(minutes))
    if minutes and minutes % 1440 == 0:
        return "{}d".format(minutes // 1440)
    if minutes and minutes % 60 == 0:
        return "{}h".format(minutes // 60)
    return "{}m".format(minutes)


def _cordon_window_ladder_minutes(threshold_minutes):
    """The fixed ladder with its first entry replaced by `threshold_minutes`
    -- the ladder always starts at the configured threshold and keeps
    whichever of the fixed, larger windows are still bigger than it."""
    ladder = [threshold_minutes]
    for minutes in _FIXED_WINDOW_LADDER_MINUTES[1:]:
        if minutes > threshold_minutes:
            ladder.append(minutes)
    return ladder


def _parse_quantity(raw):
    """Parse a Kubernetes resource.Quantity string into a float. Handles
    binary suffixes (Ki/Mi/Gi/Ti/Pi/Ei, powers of 1024), decimal SI
    suffixes (n/u/m/k/M/G/T/P/E, powers of 10), plain integers/decimals, and
    exponent forms (e.g. "1e9", parsed by plain float() once no suffix
    matches). Returns None if `raw` is missing or does not parse."""
    if raw is None:
        return None
    text = str(raw).strip()
    if not text:
        return None
    for suffix, multiplier in _BINARY_QUANTITY_SUFFIXES:
        if text.endswith(suffix):
            try:
                return float(text[: -len(suffix)]) * multiplier
            except ValueError:
                return None
    for suffix, multiplier in _DECIMAL_QUANTITY_SUFFIXES:
        if text.endswith(suffix):
            try:
                return float(text[: -len(suffix)]) * multiplier
            except ValueError:
                return None
    try:
        return float(text)
    except ValueError:
        return None


def _format_bytes(num_bytes):
    for unit, size in _BYTE_UNITS:
        if num_bytes >= size:
            return "{:.1f} {}".format(num_bytes / size, unit)
    return "{:.0f} B".format(num_bytes)




def _read_kured_daemonset(client):
    """Return the kured DaemonSet object, or None if it isn't found (wrong
    name/namespace, no DaemonSet at all, or the list itself failed --
    already recorded on client.unverifiable by list_resource)."""
    name = _kured_daemonset_name()
    daemonsets = client.list_resource("apps", "daemonsets", namespace=_kured_namespace())
    if not daemonsets:
        return None
    for ds in daemonsets:
        if (ds.get("metadata") or {}).get("name") == name:
            return ds
    return None


def _parse_kured_locks(client, daemonset):
    """Parse the kured lock annotation off `daemonset` into a list of
    {"node_id", "created" (datetime), "ttl_seconds" (float or None)} dicts
    -- [] if there is no DaemonSet or no annotation present. Handles both
    the single form ({"nodeID": ..., "created": ..., "TTL": ...}) and the
    multi form ({"maxOwners": N, "locks": [<single form>, ...]}) kured
    writes when --concurrency > 1. An annotation that is present but not
    valid JSON, or JSON that is neither of those two shapes, is recorded
    once to client.unverifiable rather than silently ignored; an individual
    lock entry missing nodeID/created is skipped on its own (nothing this
    module can use it for)."""
    if daemonset is None:
        return []
    annotations = (daemonset.get("metadata") or {}).get("annotations") or {}
    raw = annotations.get(_kured_lock_annotation())
    if not raw:
        return []

    attempted = "parse kured lock annotation {}".format(_kured_lock_annotation())
    try:
        data = json.loads(raw)
    except (TypeError, ValueError) as exc:
        client.unverifiable.append({"attempted": attempted, "detail": str(exc)})
        return []

    if isinstance(data, dict) and isinstance(data.get("locks"), list):
        entries = data["locks"]
    elif isinstance(data, dict):
        entries = [data]
    else:
        client.unverifiable.append(
            {"attempted": attempted, "detail": "annotation JSON is not an object"}
        )
        return []

    locks = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        node_id = entry.get("nodeID")
        created = _parse_ts(entry.get("created"))
        if not node_id or created is None:
            continue
        ttl_raw = entry.get("TTL")
        ttl_seconds = None
        if isinstance(ttl_raw, (int, float)) and not isinstance(ttl_raw, bool):
            ttl_seconds = ttl_raw / 1e9
        locks.append({"node_id": node_id, "created": created, "ttl_seconds": ttl_seconds})
    return locks




def _check_node_cordoned(client, now, nodes, locks_by_node, problems):
    cordoned_names = []
    for node in nodes:
        spec = node.get("spec") or {}
        name = (node.get("metadata") or {}).get("name")
        if name and spec.get("unschedulable") is True:
            cordoned_names.append(name)
    if not cordoned_names:
        return

    threshold_minutes = _cordon_max_minutes()
    threshold_seconds = threshold_minutes * 60
    ladder = _cordon_window_ladder_minutes(threshold_minutes)

    prom = prometheus.for_client(client)
    window_results = {}
    threshold_unreadable = False
    for index, window_minutes in enumerate(ladder):
        expr = "min_over_time(kube_node_spec_unschedulable[{}]) == 1".format(
            _prometheus_duration(window_minutes)
        )
        result = prom.query(expr)
        if result is None:
            if index == 0:
                threshold_unreadable = True
            break
        present = set()
        for item in result:
            node_name = (item.get("metric") or {}).get("node")
            if node_name:
                present.add(node_name)
        window_results[window_minutes] = present
        if not present:
            break

    threshold_present = window_results.get(ladder[0], set())

    for node_name in cordoned_names:
        lock = locks_by_node.get(node_name)
        lock_age_seconds = (now - lock["created"]).total_seconds() if lock else None
        lock_settles = lock_age_seconds is not None and lock_age_seconds > threshold_seconds

        if node_name in threshold_present:
            largest_window = ladder[0]
            for window_minutes, names in window_results.items():
                if node_name in names and window_minutes > largest_window:
                    largest_window = window_minutes
            since = None
            detail = "cordoned for at least {}".format(_prometheus_duration(largest_window))
            if lock is not None:
                since = _format_ts(lock["created"])
                detail += "; kured holds the reboot lock for it since {}".format(since)
            problems.append(
                _base_problem(
                    CATEGORY_CORDONED,
                    "critical",
                    "Node",
                    "v1",
                    None,
                    node_name,
                    detail,
                    cordoned_for_at_least_seconds=largest_window * 60,
                    since=since,
                    source="prometheus",
                )
            )
            continue

        if lock_settles:
            since = _format_ts(lock["created"])
            problems.append(
                _base_problem(
                    CATEGORY_CORDONED,
                    "critical",
                    "Node",
                    "v1",
                    None,
                    node_name,
                    "kured holds the reboot lock for it since {} ({}), exceeding the {} "
                    "cordon threshold".format(
                        since, _format_duration(lock_age_seconds), _prometheus_duration(threshold_minutes)
                    ),
                    cordoned_for_at_least_seconds=int(lock_age_seconds),
                    since=since,
                    source="kured-lock",
                )
            )
            continue

        if threshold_unreadable:
            problems.append(
                _base_problem(
                    CATEGORY_CORDONED,
                    "warning",
                    "Node",
                    "v1",
                    None,
                    node_name,
                    "node is cordoned now but how long could not be read "
                    "(Prometheus unreadable)",
                    cordoned_for_at_least_seconds=None,
                    since=None,
                    source="unknown",
                )
            )
            continue





def _check_kured_lock_stale(now, daemonset, locks, problems):
    if daemonset is None or not locks:
        return
    metadata = daemonset.get("metadata") or {}
    namespace = metadata.get("namespace")
    name = metadata.get("name", "<unknown>")
    fallback_seconds = _kured_lock_max_minutes() * 60

    for lock in locks:
        ttl_seconds = lock.get("ttl_seconds")
        if ttl_seconds is not None and ttl_seconds > 0:
            limit_seconds = ttl_seconds
            limit_label = _format_duration(ttl_seconds)
        else:
            limit_seconds = fallback_seconds
            limit_label = _format_duration(fallback_seconds)

        age_seconds = (now - lock["created"]).total_seconds()
        if age_seconds <= limit_seconds:
            continue

        since = _format_ts(lock["created"])
        problems.append(
            _base_problem(
                CATEGORY_KURED_LOCK_STALE,
                "critical",
                "DaemonSet",
                "apps/v1",
                namespace,
                name,
                "kured lock held by node {} since {} ({}), exceeding the {} "
                "limit".format(lock["node_id"], since, _format_duration(age_seconds), limit_label),
                node=lock["node_id"],
                since=since,
                held_for_seconds=int(age_seconds),
                limit_seconds=limit_seconds,
            )
        )




def _check_node_memory(nodes, problems):
    min_fraction = _node_memory_min_usable_fraction()
    for node in nodes:
        metadata = node.get("metadata") or {}
        name = metadata.get("name", "<unknown>")
        status = node.get("status") or {}
        capacity_raw = (status.get("capacity") or {}).get("memory")
        allocatable_raw = (status.get("allocatable") or {}).get("memory")
        capacity_bytes = _parse_quantity(capacity_raw)
        allocatable_bytes = _parse_quantity(allocatable_raw)
        if capacity_bytes is None or allocatable_bytes is None or capacity_bytes <= 0:
            continue
        fraction = allocatable_bytes / capacity_bytes
        if fraction >= min_fraction:
            continue
        problems.append(
            _base_problem(
                CATEGORY_MEMORY,
                "warning",
                "Node",
                "v1",
                None,
                name,
                "usable memory {} is {:.0f}% of {}; the rest is reserved for the "
                "system or eviction".format(
                    _format_bytes(allocatable_bytes), fraction * 100, _format_bytes(capacity_bytes)
                ),
                usable_bytes=allocatable_bytes,
                capacity_bytes=capacity_bytes,
                usable_fraction=fraction,
            )
        )


def check(client, now):
    problems = []

    nodes = client.list_resource(NODE_GROUP, NODE_RESOURCE, namespace=None)

    daemonset = _read_kured_daemonset(client)
    locks = _parse_kured_locks(client, daemonset)
    locks_by_node = {}
    for lock in locks:
        locks_by_node.setdefault(lock["node_id"], lock)

    if nodes:
        _check_node_cordoned(client, now, nodes, locks_by_node, problems)

    _check_kured_lock_stale(now, daemonset, locks, problems)

    if nodes:
        _check_node_memory(nodes, problems)

    return problems
