"""oidc-publisher: serve the cluster's public service account signing keys.

OpenRouter workload identity federation needs to fetch the cluster's OIDC
discovery document and key set from a public URL, but the API server must stay
private. This server is the only thing the public hostname reaches. It serves
exactly two paths, both fetched live from the API server with this pod's own
service account token (the system:service-account-issuer-discovery binding
lets any service account read them):

  GET /.well-known/openid-configuration  discovery, with jwks_uri rewritten
                                         to the public key URL
  GET /openid/v1/jwks                    the key set, unchanged

Everything else is 404, and nothing from the API server other than those two
documents is ever returned. Upstream answers are cached for CACHE_SECONDS so a
key rotation shows up within that window without any manual step; if the API
server is briefly unreachable the last good copy is served. The token is read
from disk on every upstream fetch because the kubelet rotates it.

GET /healthz is the liveness/readiness path (local only, never forwarded).
"""

import json
import os
import ssl
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("PORT", "8080"))
API = os.environ.get("API_SERVER", "https://kubernetes.default.svc")
PUBLIC_JWKS_URI = os.environ["PUBLIC_JWKS_URI"]
CACHE_SECONDS = int(os.environ.get("CACHE_SECONDS", "60"))
SA_DIR = os.environ.get("SA_DIR", "/var/run/secrets/kubernetes.io/serviceaccount")

DISCOVERY = "/.well-known/openid-configuration"
JWKS = "/openid/v1/jwks"

_ctx = ssl.create_default_context(cafile=os.path.join(SA_DIR, "ca.crt"))
_cache = {}
_lock = threading.Lock()


def log(level, msg, **kw):
    print(json.dumps({"level": level, "msg": msg, **kw}), flush=True)


def fetch(path):
    with open(os.path.join(SA_DIR, "token")) as f:
        token = f.read().strip()
    req = urllib.request.Request(
        API + path,
        headers={"Authorization": "Bearer " + token, "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, context=_ctx, timeout=5) as resp:
        return json.loads(resp.read())


def render(path):
    doc = fetch(path)
    if path == DISCOVERY:
        doc["jwks_uri"] = PUBLIC_JWKS_URI
    return json.dumps(doc, separators=(",", ":")).encode()


def get(path):
    now = time.monotonic()
    with _lock:
        hit = _cache.get(path)
    if hit and now - hit[0] < CACHE_SECONDS:
        return hit[1]
    try:
        body = render(path)
    except Exception as e:  # serve stale on upstream failure
        log("error", "upstream fetch failed", path=path, error=str(e))
        if hit:
            return hit[1]
        return None
    with _lock:
        _cache[path] = (now, body)
    return body


class Handler(BaseHTTPRequestHandler):
    server_version = "oidc-publisher"
    sys_version = ""

    def _send(self, code, body, ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if code == 200 and ctype == "application/json":
            self.send_header("Cache-Control", "public, max-age=%d" % CACHE_SECONDS)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/healthz":
            return self._send(200, b"ok\n", "text/plain")
        if path not in (DISCOVERY, JWKS):
            return self._send(404, b"not found\n", "text/plain")
        body = get(path)
        if body is None:
            return self._send(503, b"unavailable\n", "text/plain")
        self._send(200, body)

    do_HEAD = do_GET

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    log("info", "oidc-publisher listening", port=PORT, jwks_uri=PUBLIC_JWKS_URI)
    try:
        ThreadingHTTPServer(("", PORT), Handler).serve_forever()
    except KeyboardInterrupt:
        sys.exit(0)
