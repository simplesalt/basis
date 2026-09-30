"""alert-logger: turn Alertmanager webhook notifications into log lines.

Alertmanager POSTs its webhook payload (version 4: a JSON object with an
`alerts` array) to /alerts. This server prints ONE compact JSON line to stdout
per alert in that array -- for firing and for resolved alerts alike -- and the
cluster's log pipeline (fluent-bit -> Postgres) ingests it from there. Nothing
is stored here and no Kubernetes API is called.

Each line looks like:

    {"level":"warning","msg":"alert firing","status":"firing",
     "alertname":"KubeNodeNotReady","severity":"warning","namespace":"...",
     "node":"...","instance":"...","summary":"...","startsAt":"...",
     "endsAt":"...","fingerprint":"...","labels":{...remaining labels...}}

Why the fields are what they are:

  * `level` is what fluent-bit's grep-errors filter reads (it keeps a line if
    its parsed `level` is error/fatal/warn/warning). It is "error" for a
    critical alert and "warning" for every other severity, and it is set the
    same way for resolved alerts, so a resolved line is ingested exactly like
    the firing line that preceded it. `status` tells the two apart.
  * `msg` always contains the word "alert" plus the status.
  * `namespace`, `node` and `instance` are lifted out of the alert's labels
    when present (whatever exists is emitted, nothing is invented); every
    other label lands in `labels`. Keys that fluent-bit or the logs table
    already use at the record root (log, stream, time, kubernetes) are never
    emitted at the root, so a merged record can't clobber them.
  * `summary` is the summary annotation, else description, else message.
    `description` is added only when a summary exists and differs from it.
    Long text is truncated so a line stays well under the tail input's
    long-line limit.

The reply is 200 as soon as the lines are written. A malformed request gets a
4xx and one error-level line saying why, so a broken Alertmanager route shows
up in the same place as the alerts themselves.

GET /healthz is the liveness/readiness path.
"""

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_BODY_BYTES = 1024 * 1024
MAX_TEXT_CHARS = 1000
PROMOTED_LABELS = ("namespace", "node", "instance")
SUMMARY_ANNOTATIONS = ("summary", "description", "message")

_stdout_lock = threading.Lock()


def emit(record):
    """Write one JSON object as one line on stdout, atomically per line."""
    line = json.dumps(record, separators=(",", ":"), sort_keys=False)
    with _stdout_lock:
        sys.stdout.write(line + "\n")
        sys.stdout.flush()


def clip(value):
    text = value if isinstance(value, str) else str(value)
    if len(text) > MAX_TEXT_CHARS:
        return text[: MAX_TEXT_CHARS - 3] + "..."
    return text


def string_map(value):
    """A label/annotation map as {str: str}; anything else is empty."""
    if not isinstance(value, dict):
        return {}
    return {str(k): v if isinstance(v, str) else str(v) for k, v in value.items()}


def alert_record(alert, payload_status):
    """Build the log record for one entry of the payload's `alerts` array."""
    labels = string_map(alert.get("labels"))
    annotations = string_map(alert.get("annotations"))

    status = alert.get("status") or payload_status or "unknown"
    severity = labels.get("severity", "")
    level = "error" if severity.lower() == "critical" else "warning"

    record = {
        "level": level,
        "msg": "alert {}".format(status),
        "status": status,
        "alertname": labels.get("alertname", ""),
        "severity": severity,
    }
    for name in PROMOTED_LABELS:
        if name in labels:
            record[name] = labels[name]

    summary = next((annotations[k] for k in SUMMARY_ANNOTATIONS if annotations.get(k)), "")
    record["summary"] = clip(summary)
    description = annotations.get("description", "")
    if summary and description and description != summary:
        record["description"] = clip(description)

    record["startsAt"] = alert.get("startsAt", "")
    record["endsAt"] = alert.get("endsAt", "")
    record["fingerprint"] = alert.get("fingerprint", "")

    rest = {
        k: clip(v)
        for k, v in labels.items()
        if k not in PROMOTED_LABELS and k not in ("alertname", "severity")
    }
    if rest:
        record["labels"] = rest
    return record


def payload_records(payload):
    """One record per alert. Raises ValueError if the payload isn't usable."""
    if not isinstance(payload, dict) or not isinstance(payload.get("alerts"), list):
        raise ValueError("body is not a JSON object with an `alerts` array")
    payload_status = payload.get("status")
    return [alert_record(a, payload_status) for a in payload["alerts"] if isinstance(a, dict)]


class Handler(BaseHTTPRequestHandler):
    server_version = "alert-logger"
    timeout = 10  # a stalled client must not pin a handler thread

    def _reply(self, code, body):
        data = (json.dumps(body) + "\n").encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _reject(self, code, detail):
        emit(
            {
                "level": "error",
                "msg": "alert-logger rejected a request",
                "http_status": code,
                "detail": detail,
                "client": self.client_address[0],
            }
        )
        self._reply(code, {"error": detail})

    def do_GET(self):
        if self.path == "/healthz":
            self._reply(200, {"status": "ok"})
        else:
            self._reply(404, {"error": "not found"})

    def do_POST(self):
        if self.path.split("?", 1)[0] != "/alerts":
            self._reject(404, "POST /alerts is the only endpoint")
            return
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self._reject(411, "Content-Length is required")
            return
        if length < 0 or length > MAX_BODY_BYTES:
            self._reject(413, "body larger than {} bytes".format(MAX_BODY_BYTES))
            return
        try:
            body = self.rfile.read(length)
        except OSError:  # client stalled or went away mid-body
            self.close_connection = True
            return
        try:
            records = payload_records(json.loads(body))
        except (ValueError, UnicodeDecodeError) as exc:
            self._reject(400, str(exc))
            return
        for record in records:
            emit(record)
        self._reply(200, {"logged": len(records)})

    def log_message(self, format, *args):  # noqa: A002 - stdlib signature
        # Per-request access logging would put every kubelet probe on stderr.
        pass


def main():
    port = int(os.environ.get("PORT", "8080"))
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
