"""Minimal in-cluster Kubernetes API client, stdlib only.

Shared by finalizers.py, flux.py and crossplane.py. Every check module gets
one Client instance (constructed once by server.py) and reads/lists through
it. Two properties matter for the orphaned-finalizer scan and the checks
that will join it later:

* Nothing here hardcodes a Kind's REST path or apiVersion. `list_resource`
  and `list_deployments` resolve group/version/namespaced-ness through the
  same discovery endpoints (`/api/v1`, `/apis/<group>`, `/apis/<group>/<version>`)
  a dynamic client or kubectl would use, and cache the result per group for
  the lifetime of one /health call. That is what lets the checks walk
  RBAC-scoped groups (see platform/cluster-health.yaml's ClusterRole) without
  a table of Kind names to keep in sync by hand. Discovery only ever
  registers a resource that lists `"list"` among its `verbs` (subresources
  are skipped too, by name containing "/") -- a Kind the ClusterRole can
  read but that has no list endpoint simply never appears, rather than
  failing loudly the one time something tries to list it.

* `list_resource` also caches its own return value per (group, resource,
  namespace) for the lifetime of this Client -- one /health call. finalizers.py,
  flux.py and crossplane.py all ask for several of the same cluster-wide
  lists (Kustomizations, HelmReleases, Sources, CustomResourceDefinitions,
  Providers, ProviderRevisions, and now every Kind under every group the
  ClusterRole grants), and each Client is constructed fresh per request (see
  server.py's run_checks), so this cache is naturally per-request, never
  stale across calls, and never shared between concurrent requests.

* A failed or denied call never raises out of `list_resource` /
  `list_deployments` / `get_safe`. It is recorded on `self.unverifiable` --
  {"attempted": ..., "detail": ...} -- and the caller gets back `None`
  (distinct from `[]`, which means the call succeeded and found nothing, or
  the group/resource genuinely does not exist in this cluster). server.py
  reads `client.unverifiable` after running every check to fill the
  `/health` response's `unverifiable` field, so nothing is ever silently
  swallowed as an empty result.
"""

import json
import ssl
import urllib.error
import urllib.parse
import urllib.request

SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"


class ApiError(Exception):
    """A Kubernetes API call did not return a usable 2xx response."""

    def __init__(self, method, path, status, detail):
        self.method = method
        self.path = path
        self.status = status
        self.detail = detail
        super().__init__(
            "{} {} -> {}: {}".format(method, path, status, detail)
        )


class Client:
    def __init__(self, host, port, ca_path=SA_DIR + "/ca.crt", token_path=SA_DIR + "/token"):
        self.base_url = "https://{}:{}".format(host, port)
        self.ctx = ssl.create_default_context(cafile=ca_path)
        self.token_path = token_path
        self.unverifiable = []
        self._discovery_cache = {}
        self._deployment_cache = {}
        self._list_cache = {}

    @classmethod
    def in_cluster(cls):
        import os

        return cls(
            os.environ["KUBERNETES_SERVICE_HOST"],
            os.environ["KUBERNETES_SERVICE_PORT"],
        )

    def _token(self):
        # Re-read on every call rather than caching: kubelet rotates a
        # projected SA token in place, and this process is meant to run for
        # a long time between pod restarts.
        with open(self.token_path) as handle:
            return handle.read().strip()

    def get(self, path, params=None):
        """GET a JSON path. Raises ApiError on anything but 2xx."""
        query = ""
        if params:
            query = "?" + urllib.parse.urlencode(params)
        url = self.base_url + path + query
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": "Bearer " + self._token(),
                "Accept": "application/json",
            },
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=20) as resp:
                body = resp.read()
                return json.loads(body) if body else {}
        except urllib.error.HTTPError as exc:
            detail = exc.read()
            try:
                detail = detail.decode("utf-8", "replace")
            except Exception:
                detail = str(detail)
            raise ApiError("GET", path, exc.code, detail[:500]) from None
        except urllib.error.URLError as exc:
            raise ApiError("GET", path, None, str(exc.reason)) from None

    def get_safe(self, path, attempted, params=None):
        """GET a JSON path; record failure to self.unverifiable and return
        None instead of raising."""
        try:
            return self.get(path, params=params)
        except ApiError as exc:
            self.unverifiable.append({"attempted": attempted, "detail": str(exc)})
            return None

    def _discover_group(self, group):
        """Return ("ok", version, {resource: namespaced}), ("absent", None,
        None) if the group/version is not registered in this cluster, or
        ("error", None, None) if discovery failed for another reason (and
        was recorded to self.unverifiable)."""
        try:
            if group == "":
                body = self.get("/api/v1")
                version = "v1"
            else:
                group_doc = self.get("/apis/{}".format(group))
                version = (group_doc.get("preferredVersion") or {}).get("version")
                if not version:
                    versions = group_doc.get("versions") or []
                    version = versions[0]["version"] if versions else None
                if not version:
                    return ("absent", None, None)
                body = self.get("/apis/{}/{}".format(group, version))
        except ApiError as exc:
            if exc.status == 404:
                return ("absent", None, None)
            self.unverifiable.append(
                {
                    "attempted": "discover API group {!r}".format(group or "core/v1"),
                    "detail": str(exc),
                }
            )
            return ("error", None, None)

        resources = {}
        for entry in body.get("resources", []):
            name = entry.get("name", "")
            if "/" in name:
                continue  # skip subresources (pods/log, deployments/status, ...)
            if "list" not in (entry.get("verbs") or []):
                continue  # e.g. bindings, tokenreviews -- create-only, no list
            resources[name] = bool(entry.get("namespaced"))
        return ("ok", version, resources)

    def resolve(self, group, resource):
        """("ok", version, namespaced) | ("absent", None, None) | ("error", None, None)."""
        if group not in self._discovery_cache:
            self._discovery_cache[group] = self._discover_group(group)
        status, version, resources = self._discovery_cache[group]
        if status != "ok":
            return (status, None, None)
        if resource not in resources:
            return ("absent", None, None)
        return ("ok", version, resources[resource])

    def list_resource(self, group, resource, namespace=None):
        """List every object of `resource` in API group `group` (empty
        string for core/v1).

        namespace=None lists cluster-wide: every namespace for a namespaced
        resource, or the single collection for a cluster-scoped one.
        Returns a list (possibly empty, including when the group/resource
        does not exist in this cluster -- that is a verified absence, not a
        failure) or None if the call could not be verified (already
        recorded on self.unverifiable).

        Cached per (group, resource, namespace) for the lifetime of this
        Client -- one /health call -- so finalizers.py, flux.py and
        crossplane.py can each ask for the same cluster-wide list (e.g.
        Kustomizations, CustomResourceDefinitions, Providers) without
        issuing it more than once. A failed call's None is cached too: a
        denied list is not retried, and does not get recorded to
        self.unverifiable a second time.
        """
        cache_key = (group, resource, namespace)
        if cache_key in self._list_cache:
            return self._list_cache[cache_key]

        status, version, namespaced = self.resolve(group, resource)
        if status == "absent":
            result = []
        elif status == "error":
            result = None
        else:
            base = "/apis/{}/{}".format(group, version) if group else "/api/{}".format(version)
            if namespaced and namespace:
                path = "{}/namespaces/{}/{}".format(base, namespace, resource)
                scope = "namespace {}".format(namespace)
            else:
                path = "{}/{}".format(base, resource)
                scope = "namespace {}".format(namespace) if namespace else "cluster-wide"
            attempted = "list {}{} ({})".format(
                resource, "." + group if group else "", scope
            )
            body = self.get_safe(path, attempted)
            result = None if body is None else body.get("items", [])

        self._list_cache[cache_key] = result
        return result

    def group_resources(self, group):
        """Every top-level resource name registered under `group`, e.g. to
        walk "the Flux and Crossplane kinds" without hardcoding each Kind.
        Returns a list of (resource, namespaced) pairs, or None on failure."""
        status, _version, resources = self.resolve_group(group)
        if status == "absent":
            return []
        if status == "error":
            return None
        return sorted(resources.items())

    def resolve_group(self, group):
        if group not in self._discovery_cache:
            self._discovery_cache[group] = self._discover_group(group)
        return self._discovery_cache[group]

    def list_deployments(self, namespace):
        """List every Deployment in `namespace`, unfiltered, cached for the
        lifetime of this Client (one /health call) the same way `resolve`
        caches discovery per group.

        No server-side label selector: several Deployments these checks care
        about carry no top-level metadata.labels at all (every Crossplane
        provider runtime pod -- see crossplane.py's module docstring) or
        omit the specific key a hand-written selector guessed (the Flux
        controllers only carry `app=<name>` in spec.template.metadata.labels
        / spec.selector.matchLabels, not at the top level). Callers
        (finalizers.classify_controller, crossplane.check) list the whole
        namespace once and match client-side against the Deployment's own
        template/selector labels instead.

        Returns a list, or None if the lookup could not be verified (already
        recorded on self.unverifiable)."""
        if namespace in self._deployment_cache:
            return self._deployment_cache[namespace]

        status, version, _namespaced = self.resolve("apps", "deployments")
        if status == "absent":
            result = []
        elif status == "error":
            result = None
        else:
            path = "/apis/apps/{}/namespaces/{}/deployments".format(version, namespace)
            attempted = "list deployments in {}".format(namespace)
            body = self.get_safe(path, attempted)
            result = None if body is None else body.get("items", [])

        self._deployment_cache[namespace] = result
        return result
