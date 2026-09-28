"""cluster-health HTTP server.

GET /health runs every check module (finalizers implemented; flux and
crossplane are stubs returning [] until later tasks fill them in) against a
fresh in-cluster API client and returns:

    {
      "checked_at": "<RFC3339 timestamp>",
      "problems": [{category, severity, kind, apiVersion, namespace, name,
                    detail, ...}],
      "counts": {...},
      "unverifiable": [{"attempted": ..., "detail": ...}]
    }

`unverifiable` is never silently empty because it isn't hand-maintained: it
is exactly whatever client.py's Client recorded while every check ran (see
client.py's module docstring), read back after all three checks return.

GET /healthz is a separate, cheap liveness/readiness path that never calls
the Kubernetes API, so kubelet probing this pod doesn't itself hammer the
API server or flap readiness on a slow cluster-wide scan.
"""

import json
import os
import sys
import traceback
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(__file__))

import client as client_mod  # noqa: E402
import crossplane  # noqa: E402
import finalizers  # noqa: E402
import flux  # noqa: E402

CHECKS = (finalizers, flux, crossplane)


def run_checks():
    now = datetime.now(timezone.utc).replace(microsecond=0)
    api = client_mod.Client.in_cluster()

    problems = []
    for module in CHECKS:
        try:
            problems.extend(module.check(api, now))
        except Exception:  # a check module bug must not blank the response
            api.unverifiable.append(
                {
                    "attempted": "run {}.check()".format(module.__name__),
                    "detail": traceback.format_exc(limit=8),
                }
            )

    counts = {"problems": len(problems), "unverifiable": len(api.unverifiable)}
    by_category = {}
    by_severity = {}
    for problem in problems:
        by_category[problem.get("category", "unknown")] = (
            by_category.get(problem.get("category", "unknown"), 0) + 1
        )
        by_severity[problem.get("severity", "unknown")] = (
            by_severity.get(problem.get("severity", "unknown"), 0) + 1
        )
    counts["by_category"] = by_category
    counts["by_severity"] = by_severity

    return {
        "checked_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "problems": problems,
        "counts": counts,
        "unverifiable": api.unverifiable,
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "cluster-health/1.0"

    def _write_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            try:
                self._write_json(200, run_checks())
            except Exception:
                self._write_json(
                    500,
                    {
                        "error": "cluster-health failed to run its checks",
                        "detail": traceback.format_exc(limit=8),
                    },
                )
            return
        if self.path in ("/healthz", "/livez", "/readyz"):
            self._write_json(200, {"status": "ok"})
            return
        self._write_json(404, {"error": "not found"})

    def log_message(self, fmt, *args):  # keep default stderr logging, just tagged
        sys.stderr.write("cluster-health: " + (fmt % args) + "\n")


def main():
    port = int(os.environ.get("PORT", "8080"))
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
