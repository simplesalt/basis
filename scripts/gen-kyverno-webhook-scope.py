#!/usr/bin/env python3
import io
import json
import os
import pathlib
import re
import subprocess
import sys
import tarfile
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
CONTROLLERS = ROOT / "operators" / "controllers.yaml"
HELMREPOS = ROOT / "operators" / "helmrepos.yaml"
OUTPUT = ROOT / "operators" / "kyverno-webhook-scope.generated.yaml"
RELEASE = 'select(.kind == "HelmRelease" and .metadata.name == "kyverno")'
NAMESPACE_OBJECT = "request.resource.group == '' && request.resource.version == 'v1' && request.resource.resource == 'namespaces'"


def yq_json(expr, path=None, data=None):
    args = ["yq", "-o=json", expr] + ([str(path)] if path else ["-"])
    out = subprocess.run(args, input=data, capture_output=True, check=True).stdout
    return json.loads(out)


def fetch(url):
    with urllib.request.urlopen(url, timeout=60) as response:
        return response.read()


def chart_values(release):
    spec = release["spec"]["chart"]["spec"]
    repo = yq_json(f'select(.kind == "HelmRepository" and .metadata.name == "{spec["sourceRef"]["name"]}") | .spec.url', HELMREPOS)
    index = yq_json(f'.entries["{spec["chart"]}"][] | select(.version == "{spec["version"]}") | .urls', data=fetch(repo.rstrip("/") + "/index.yaml"))
    url = index[0] if re.match(r"^https?://", index[0]) else repo.rstrip("/") + "/" + index[0]
    with tarfile.open(fileobj=io.BytesIO(fetch(url))) as archive:
        values = archive.extractfile(f'{spec["chart"]}/values.yaml').read()
    return yq_json(".", data=values)


def merge(base, override):
    if isinstance(base, dict) and isinstance(override, dict):
        return {k: merge(base.get(k), override[k]) if k in override else base[k] for k in {**base, **override}}
    return override if override is not None else base


def resource_filters(config, namespace):
    filters = list(config.get("resourceFilters") or [])
    if config.get("excludeKyvernoNamespace"):
        filters = [f"[*/*,{namespace},*]"] + filters
    for item in config.get("resourceFiltersExclude") or []:
        filters = [f for f in filters if f != item]
    for item in config.get("resourceFiltersExcludeNamespaces") or []:
        filters = [f for f in filters if f",{item}," not in f]
    filters += config.get("resourceFiltersInclude") or []
    filters += [f"[*/*,{item},*]" for item in config.get("resourceFiltersIncludeNamespaces") or []]
    return [f for f in filters if "{{" not in f]


def parse_kind(kind):
    parts = kind.split("/")
    parts = parts[:-1] + parts[-1].split(".")
    version = re.compile(r"^v\d+((alpha|beta)\d+)?$|^\*$")
    if len(parts) == 1:
        return "*", "*", parts[0], ""
    if len(parts) == 2:
        if parts == ["*", "*"]:
            return "*", "*", "*", "*"
        if parts[0] == "*" and parts[1].lower() == parts[1]:
            return "*", "*", parts[0], parts[1]
        if version.match(parts[0]):
            return "*", parts[0], parts[1], ""
        return "*", "*", parts[0], parts[1]
    if len(parts) == 3:
        if version.match(parts[0]):
            return "*", parts[0], parts[1], parts[2]
        return parts[0], parts[1], parts[2], ""
    if len(parts) == 4:
        return parts[0], parts[1], parts[2], parts[3]
    return None


def parse_filters(filters):
    out = []
    for item in re.findall(r"\[([^\[\]]*)\]", " ".join(filters)):
        fields = item.split(",")
        fields += [""] * (3 - len(fields))
        if not fields[0] or len(fields) > 3:
            continue
        kind = parse_kind(fields[0])
        if kind:
            out.append((*kind, fields[1], fields[2]))
    return out


def lit(value):
    return json.dumps(value)


def glob(pattern, field):
    if pattern == "*":
        return "true"
    if "*" not in pattern and "?" not in pattern:
        return f"{field} == {lit(pattern)}"
    regex = "^" + "".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in pattern) + "$"
    return f"{field}.matches({lit(regex)})"


def plural(kind):
    kind = kind.lower()
    if kind.endswith("y"):
        return kind[:-1] + "ies"
    if kind.endswith(("s", "x", "ch", "sh")):
        return kind + "es"
    return kind + "s"


def conj(*terms):
    terms = [t for t in terms if t != "true"]
    if "false" in terms:
        return "false"
    return " && ".join(f"({t})" for t in terms) or "true"


def disj(*terms):
    terms = [t for t in terms if t != "false"]
    if "true" in terms:
        return "true"
    return " || ".join(f"({t})" for t in terms) or "false"


def kind_term(kind, sub):
    if kind == "*":
        return "true"
    whole = conj("request.subResource == ''", glob(kind, "request.kind.kind"))
    if sub == "":
        return whole
    part = "false" if "*" in kind or "?" in kind else conj("request.subResource != ''", f"request.resource.resource == {lit(plural(kind))}")
    return part if sub == "?*" else disj(whole, part)


def filter_term(group, version, kind, sub, namespace, name):
    subresource = "request.subResource == ''" if sub == "" else "request.subResource != ''" if sub == "?*" else glob(sub, "request.subResource")
    kind = kind_term(kind, sub)
    scope = disj(
        conj(glob(namespace, "request.namespace"), glob(name, "request.name")),
        conj(NAMESPACE_OBJECT, glob(namespace, "request.name")),
    )
    return conj(glob(group, "request.resource.group"), glob(version, "request.resource.version"), kind, subresource, scope)


def filters_expression(filters):
    whole_kinds, namespaces, rest = [], [], []
    for f in filters:
        group, version, kind, sub, namespace, name = f
        if (group, version, sub, namespace, name) == ("*", "*", "", "*", "*") and "*" not in kind and "?" not in kind:
            whole_kinds.append(kind)
        elif (group, version, kind, sub, name) == ("*", "*", "*", "*", "*") and "*" not in namespace and "?" not in namespace:
            namespaces.append(namespace)
        else:
            rest.append(filter_term(*f))
    terms = []
    if whole_kinds:
        terms.append(f"request.subResource == '' && request.kind.kind in [{', '.join(lit(k) for k in dict.fromkeys(whole_kinds))}]")
    if namespaces:
        names = ", ".join(lit(n) for n in dict.fromkeys(namespaces))
        terms.append(f"request.namespace in [{names}] || ({NAMESPACE_OBJECT} && request.name in [{names}])")
    terms += rest
    return f"!({disj(*terms)})"


def split_exclusions(value):
    items = [i.strip() for i in (value if isinstance(value, list) else str(value or "").split(",")) if i and i.strip()]
    return [i for i in items if not i.startswith("!")], [i[1:].strip() for i in items if i.startswith("!") and i[1:].strip()]


def users_expression(config):
    groups, include_groups = split_exclusions(config.get("excludeGroups"))
    users, include_users = split_exclusions(config.get("excludeUsernames"))
    if config.get("excludeRoles") or config.get("excludeClusterRoles") or not (groups or users):
        return None
    def any_group(patterns):
        return f"has(request.userInfo.groups) && request.userInfo.groups.exists(g, {disj(*[glob(p, 'g') for p in patterns])})"
    def any_user(patterns):
        return disj(*[glob(p, "request.userInfo.username") for p in patterns])
    excluded = disj(*([any_group(groups)] if groups else []), *([any_user(users)] if users else []))
    included = disj(*([any_group(include_groups)] if include_groups else []), *([any_user(include_users)] if include_users else []))
    return f"!({excluded})" if included == "false" else f"({included}) || !({excluded})"


def main():
    release = yq_json(RELEASE, CONTROLLERS)
    namespace = release["spec"].get("targetNamespace") or release["metadata"]["namespace"]
    ours = (release["spec"].get("values") or {}).get("config") or {}
    config = merge(chart_values(release).get("config") or {}, {k: v for k, v in ours.items() if k != "matchConditions"})
    conditions = [{"name": "kyverno-resource-filters", "expression": filters_expression(parse_filters(resource_filters(config, namespace)))}]
    users = users_expression(config)
    if users:
        conditions.append({"name": "kyverno-excluded-users", "expression": users})
    values = subprocess.run(["yq", "-P", "."], input=json.dumps({"config": {"matchConditions": conditions}}).encode(), capture_output=True, check=True).stdout
    OUTPUT.write_bytes(values)
    sys.stdout.write(values.decode())


if __name__ == "__main__":
    main()
