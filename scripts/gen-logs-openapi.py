#!/usr/bin/env python3
"""Convert PostgREST's Swagger 2.0 self-description to OpenAPI 3.0.

PostgREST emits Swagger 2.0 and will not change: the OpenAPI 3.0 request has
been open upstream since 2017 (postgrest#932) and a 2020 proposal
(postgrest#1698) moves spec generation out of core entirely. agentgateway
parses with the openapiv3 Rust crate and reads 3.0 only, failing with
"paths: no variant of enum ParameterSchemaOrContent found in flattened data".

The two dialects describe the same API, so this is a rename-and-reshape of a
JSON document, not a reimplementation. Running it at commit time rather than in
the request path is what keeps the design free of an owned image and a build
step -- agentgateway's schema source accepts a file, so the converted document
ships in the logs-mcp ConfigMap.

The output is a generated artifact, in the sense a lock file is. Regenerate it
in the same commit as any change to the logs_api semantic layer in
platform/logs-pg.yaml, or the MCP tool list silently goes stale.

    scripts/gen-logs-openapi.py \
        --url http://logs-postgrest.cluster-main-observability.svc.cluster.local:3000/ \
        --configmap --out platform/logs-mcp-openapi.yaml
"""

import argparse
import json
import sys
import urllib.request

# Formats OpenAPI 3.0 names explicitly. PostgREST emits the underlying Postgres
# type instead ("text", "timestamp without time zone", "character varying"),
# which is legal as an open-ended format string but is noise to a consumer that
# cannot interpret it. Dropping the unknown ones keeps the document to formats
# a strict parser is guaranteed to accept.
KNOWN_FORMATS = {
    "int32", "int64", "float", "double", "byte",
    "binary", "date", "date-time", "password",
}

# Keys that belong on a Schema Object once a Swagger 2.0 parameter is reshaped.
# Everything else on the parameter (name, in, required, description) stays put.
SCHEMA_KEYS = {
    "type", "format", "items", "enum", "default", "maximum", "minimum",
    "exclusiveMaximum", "exclusiveMinimum", "maxLength", "minLength",
    "pattern", "maxItems", "minItems", "uniqueItems", "multipleOf",
}

# logs_read holds no write grant anywhere, so PostgREST advertising these is
# advertising operations that always fail. follow-privileges was expected to
# suppress them and does not. Each one would otherwise become an MCP tool that
# exists only to return a permission error.
WRITE_METHODS = {"post", "put", "patch", "delete"}


def rewrite_refs(node):
    """Repoint every $ref from Swagger 2.0 containers to OpenAPI 3.0 ones."""
    if isinstance(node, dict):
        out = {}
        for key, value in node.items():
            if key == "$ref" and isinstance(value, str):
                out[key] = (
                    value
                    .replace("#/definitions/", "#/components/schemas/")
                    .replace("#/parameters/", "#/components/parameters/")
                    .replace("#/responses/", "#/components/responses/")
                )
            else:
                out[key] = rewrite_refs(value)
        return out
    if isinstance(node, list):
        return [rewrite_refs(item) for item in node]
    return node


def clean_schema(schema):
    """Strip Postgres-native format strings from a schema and its children."""
    if isinstance(schema, dict):
        out = {}
        for key, value in schema.items():
            if key == "format" and value not in KNOWN_FORMATS:
                continue
            out[key] = clean_schema(value)
        return out
    if isinstance(schema, list):
        return [clean_schema(item) for item in schema]
    return schema


def convert_parameter(param):
    """Hoist a Swagger 2.0 parameter's type keywords into a schema object.

    This single reshape is the actual cause of the agentgateway parse failure:
    OpenAPI 3.0 requires every non-body parameter to carry either `schema` or
    `content`, and Swagger 2.0 puts `type`/`format`/`items` directly on the
    parameter instead.
    """
    if "$ref" in param:
        return dict(param)

    converted = {}
    schema = {}
    for key, value in param.items():
        if key in SCHEMA_KEYS:
            schema[key] = value
        elif key != "collectionFormat":
            converted[key] = value

    if not schema:
        schema = {"type": "string"}
    converted["schema"] = clean_schema(schema)
    return converted


def convert_responses(responses, produces):
    """Move a response's `schema` under a media type, per OpenAPI 3.0."""
    media_types = produces or ["application/json"]
    out = {}
    for code, response in responses.items():
        converted = {
            k: v for k, v in response.items() if k not in ("schema", "examples")
        }
        converted.setdefault("description", "")
        if "schema" in response:
            schema = clean_schema(response["schema"])
            converted["content"] = {mt: {"schema": schema} for mt in media_types}
        out[code] = converted
    return out


def operation_id(path, method):
    """Derive a stable tool name.

    PostgREST emits no operationId, and agentgateway names each MCP tool after
    it. Without this every tool would fall back to a generated name and the
    stored queries would not be addressable as `recent`, `errors`, `search`
    and so on.
    """
    if path.startswith("/rpc/"):
        return path[len("/rpc/"):]
    return path.lstrip("/").replace("/", "_") or "root"


def convert_operation(path, method, operation, default_produces):
    converted = {
        k: v for k, v in operation.items()
        if k not in ("parameters", "responses", "produces", "consumes", "schemes")
    }
    converted["operationId"] = operation_id(path, method)

    params = [
        convert_parameter(p)
        for p in operation.get("parameters", [])
        if p.get("in") != "body"
    ]
    if params:
        converted["parameters"] = params

    produces = operation.get("produces", default_produces)
    converted["responses"] = convert_responses(
        operation.get("responses", {"200": {"description": "OK"}}), produces
    )
    return converted


def convert(spec):
    if spec.get("swagger") != "2.0":
        raise SystemExit(
            f"expected a Swagger 2.0 document, got {spec.get('swagger') or spec.get('openapi')!r}"
        )

    default_produces = spec.get("produces")

    paths = {}
    for path, item in spec.get("paths", {}).items():
        # The root path serves this very document. As a tool it would hand an
        # agent the API description it already has.
        if path == "/":
            continue
        operations = {}
        for method, operation in item.items():
            if method in WRITE_METHODS or not isinstance(operation, dict):
                continue
            operations[method] = convert_operation(
                path, method, operation, default_produces
            )
        if operations:
            paths[path] = operations

    components = {}
    if "definitions" in spec:
        components["schemas"] = clean_schema(spec["definitions"])
    if "parameters" in spec:
        components["parameters"] = {
            name: convert_parameter(param)
            for name, param in spec["parameters"].items()
            if param.get("in") != "body"
        }

    out = {
        "openapi": "3.0.3",
        "info": spec.get("info", {"title": "logs", "version": "1"}),
        # Relative, because agentgateway is configured with the upstream host
        # separately. Swagger 2.0's host/basePath/schemes named 0.0.0.0:3000,
        # PostgREST's own bind address, which is not reachable as written.
        "servers": [{"url": "/"}],
        "paths": paths,
    }
    if "externalDocs" in spec:
        out["externalDocs"] = spec["externalDocs"]
    if components:
        out["components"] = components

    return rewrite_refs(out)


CONFIGMAP_HEADER = """---
# GENERATED FILE -- DO NOT EDIT BY HAND.
#
#   scripts/gen-logs-openapi.py \\
#       --url http://logs-postgrest.cluster-main-observability.svc.cluster.local:3000/ \\
#       --configmap --out platform/logs-mcp-openapi.yaml
#
# PostgREST's own OpenAPI description of the logs_api semantic layer, converted
# from the Swagger 2.0 it emits to the OpenAPI 3.0 agentgateway can parse. See
# the script for why the conversion happens here rather than in the request
# path. Regenerate in the same commit as any change to the logs_api schema in
# logs-pg.yaml, or the MCP tool list silently goes stale.
apiVersion: v1
kind: ConfigMap
metadata:
  name: logs-mcp-openapi
  namespace: cluster-main-observability
  labels:
    app.kubernetes.io/name: logs-mcp
    app.kubernetes.io/part-of: observability
    app.kubernetes.io/component: mcp-server
    entity: cluster
    env: main
    capability: observability
data:
  openapi.json: |
"""


def as_configmap(text):
    body = "".join(f"    {line}\n" for line in text.splitlines())
    return CONFIGMAP_HEADER + body


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--url", help="PostgREST root URL to fetch the spec from")
    source.add_argument("--in", dest="infile", help="read a saved spec instead")
    parser.add_argument("--out", help="write here instead of stdout")
    parser.add_argument(
        "--configmap",
        action="store_true",
        help="wrap the spec in the logs-mcp-openapi ConfigMap manifest",
    )
    args = parser.parse_args()

    if args.url:
        with urllib.request.urlopen(args.url, timeout=30) as response:
            spec = json.load(response)
    else:
        with open(args.infile) as handle:
            spec = json.load(handle)

    converted = convert(spec)
    text = json.dumps(converted, indent=2, sort_keys=True) + "\n"
    if args.configmap:
        text = as_configmap(text)

    if args.out:
        with open(args.out, "w") as handle:
            handle.write(text)
    else:
        sys.stdout.write(text)

    tools = sum(len(ops) for ops in converted["paths"].values())
    print(f"{tools} operations across {len(converted['paths'])} paths", file=sys.stderr)


if __name__ == "__main__":
    main()
