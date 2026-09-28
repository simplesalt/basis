"""Minimal stdlib Prometheus HTTP client.

Shared by alerts.py (and any check module that follows it) so a health run
can read live alerting/metric state from Prometheus alongside the
Kubernetes API reads client.py already does -- same failure discipline as
client.py's Client: nothing here ever raises out to a caller. A failed
request (HTTP error, timeout, URL error, bad JSON, status != "success", or
an unexpected resultType) is recorded on `unverifiable` -- the very list
client.Client.unverifiable already is, passed in by for_client below -- and
the caller gets back None, exactly like client.py's get_safe/list_resource.

One Prometheus instance is meant to live for one /health call, the same
lifetime as one Client: `for_client(client)` constructs it once per Client
and stashes it on `client.prometheus`, so every check module in that run
that asks for Prometheus data shares one instance, one HTTP timeout budget,
and one cache -- a second module asking for the same alerts list or the same
query expression within that run costs no extra request.
"""

import json
import os
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_PROMETHEUS_URL = (
    "http://prometheus-operated.cluster-main-observability.svc.cluster.local:9090"
)
PROMETHEUS_URL = os.environ.get("PROMETHEUS_URL", DEFAULT_PROMETHEUS_URL)

TIMEOUT_SECONDS = 10


class Prometheus:
    def __init__(self, base_url, unverifiable):
        self.base_url = base_url
        self.unverifiable = unverifiable
        self._alerts_fetched = False
        self._alerts_cache = None
        self._query_cache = {}

    def _fetch(self, path, params=None):
        """One GET attempt against `path`, no retry. Returns the parsed JSON
        body. Raises on anything that makes the response unusable -- an HTTP
        error, a timeout/URLError, or a body that isn't valid JSON. Kept in
        its own method, like client.Client._fetch, so a test can override
        just this one HTTP call and still exercise the real caching/parsing
        in `alerts`/`query` below."""
        query = ""
        if params:
            query = "?" + urllib.parse.urlencode(params)
        url = self.base_url + path + query
        req = urllib.request.Request(url, headers={"Accept": "application/json"}, method="GET")
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
            body = resp.read()
        return json.loads(body)

    def _get(self, path, attempted, params=None):
        """GET `path`, returning its "data" field on a
        {"status": "success", "data": ...} response, or None -- recorded
        once to self.unverifiable -- on any failure: the HTTP attempt itself
        raising, a non-dict body, or status != "success" (Prometheus's own
        shape for a query error, e.g. a bad PromQL expression)."""
        try:
            body = self._fetch(path, params=params)
        except Exception as exc:
            self.unverifiable.append({"attempted": attempted, "detail": str(exc)})
            return None
        if not isinstance(body, dict) or body.get("status") != "success":
            detail = body.get("error") if isinstance(body, dict) else None
            self.unverifiable.append(
                {
                    "attempted": attempted,
                    "detail": "status != \"success\": {}".format(detail or body),
                }
            )
            return None
        return body.get("data")

    def alerts(self):
        """GET /api/v1/alerts -> data.alerts (a list of alert dicts), or
        None on any failure (recorded once to self.unverifiable). Cached for
        the lifetime of this instance: a second call, from this module or
        another sharing the same Prometheus (see for_client), never issues a
        second request."""
        if self._alerts_fetched:
            return self._alerts_cache
        self._alerts_fetched = True

        attempted = "GET /api/v1/alerts"
        data = self._get("/api/v1/alerts", attempted)
        alerts = None
        if data is not None:
            candidate = data.get("alerts")
            if isinstance(candidate, list):
                alerts = candidate
            else:
                self.unverifiable.append(
                    {"attempted": attempted, "detail": "data.alerts missing or not a list"}
                )
        self._alerts_cache = alerts
        return alerts

    def query(self, expr):
        """GET /api/v1/query?query=<expr> -> data.result (a list of vector
        samples, [{"metric": {...}, "value": [ts, "str"]}]), or None on any
        failure, including a resultType other than "vector" (recorded once
        to self.unverifiable). Cached per `expr` for the lifetime of this
        instance."""
        if expr in self._query_cache:
            return self._query_cache[expr]

        attempted = "query {!r}".format(expr)
        data = self._get("/api/v1/query", attempted, params={"query": expr})
        result = None
        if data is not None:
            result_type = data.get("resultType")
            if result_type != "vector":
                self.unverifiable.append(
                    {
                        "attempted": attempted,
                        "detail": "resultType {!r} != \"vector\"".format(result_type),
                    }
                )
            else:
                items = data.get("result")
                if isinstance(items, list):
                    result = items
                else:
                    self.unverifiable.append(
                        {"attempted": attempted, "detail": "data.result missing or not a list"}
                    )
        self._query_cache[expr] = result
        return result


def for_client(client):
    """Return the Prometheus instance shared by every check module within
    one /health call. A test injects a fake by setting `client.prometheus`
    itself before calling check(); otherwise the first module to ask builds
    a real Prometheus against PROMETHEUS_URL, sharing `client.unverifiable`
    so its failures land in the same place a failed Kubernetes read would,
    and stashes it on `client.prometheus` for every later caller in this
    same run to reuse."""
    existing = getattr(client, "prometheus", None)
    if existing is not None:
        return existing
    instance = Prometheus(PROMETHEUS_URL, client.unverifiable)
    client.prometheus = instance
    return instance
