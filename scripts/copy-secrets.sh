#!/usr/bin/env bash
#
# copy-secrets.sh -- copy manually-populated Secret payloads from the OLD cluster
# (k1.famevans.win) to the NEW cluster, one Secret at a time, without ever
# writing a payload to disk, to a log line, or to a process argument list.
#
# WHY THIS EXISTS. Every Secret here is declared by Flux as an empty placeholder
# and filled in by hand (see platform/human-operator.yaml). Those hand-supplied
# values are the one part of cluster state that is NOT reproducible from Git, so
# they are the one part a rebuild has to physically carry across.
#
# HOW IT MOVES THE PAYLOAD.
#   * Reads `.data` from the old Secret (already base64, exactly as stored) and
#     nothing else. Never metadata: copying metadata forward would drag the old
#     cluster's resourceVersion/ownership/annotations along, and if the source
#     ever picked up a kubectl.kubernetes.io/last-applied-configuration the
#     reject-last-applied-on-secrets ClusterPolicy (platform/policies.secrets.yaml)
#     would reject the write on arrival.
#   * Writes with `kubectl patch --type merge`, never `kubectl apply`. Client-side
#     apply copies the payload into the last-applied annotation, which is the
#     exact exposure that ClusterPolicy exists to deny. A merge patch on `data`
#     also merges rather than replaces, so keys already on the target that this
#     script does not name are left alone.
#   * Feeds the patch in on stdin via `--patch-file /dev/stdin`, so the payload
#     never appears in `ps` output.
#   * Never uses a bash here-string or here-doc for payload data. Bash implements
#     both by writing to a temp file, which would put plaintext on disk for as
#     long as the redirect lives. Payload moves through pipes and shell variables
#     only, and each variable is cleared at the end of its iteration.
#
# THE TARGET SECRET MUST ALREADY EXIST. `patch` cannot create, and the
# human-operator identity is denied `create` on purpose. A missing target means
# Flux has not declared it on the new cluster yet -- that is a manifest gap to
# fix in Git, not something to paper over here, so the script reports it and
# moves on.
#
# USAGE
#   OLD_KUBECONFIG=/path/to/old-cluster.kubeconfig ./scripts/copy-secrets.sh
#   OLD_KUBECONFIG=/path/to/old-cluster.kubeconfig ./scripts/copy-secrets.sh --apply
#
#   Dry run is the default and reports, per key, whether the target is absent,
#   already identical, or holds a different value that --apply would overwrite.
#   It never prints a value, in either mode.
#
#   Optional filter args match a Secret's old or new name, so a single row can be
#   rehearsed on its own:
#     ./scripts/copy-secrets.sh --apply gbrain-embedding-secret
#
# ENVIRONMENT
#   OLD_KUBECONFIG  (required) path to the old cluster's kubeconfig
#   OLD_CONTEXT     (optional) context within it; defaults to its current-context
#   NEW_KUBECONFIG  (optional) defaults to the ambient KUBECONFIG / ~/.kube/config
#   NEW_CONTEXT     (optional) context within that; defaults to its current-context
#
#   Note --context, not --cluster: a `cluster` entry is only a server URL and CA,
#   with no user attached, so `kubectl --cluster=...` would authenticate as
#   whatever the current context's user happens to be.

set -euo pipefail

# Refuse to run traced. `set -x` on this script would echo every payload-bearing
# expansion to stderr, which defeats every other precaution above.
case "$-" in
  *x*) echo "refusing to run under 'set -x': tracing would echo secret payloads" >&2; exit 2 ;;
esac
umask 077

# --------------------------------------------------------------------------
# The work list.
#
#   old_ns | old_name | new_ns | new_name | keys
#
# `keys` is a comma-separated allow-list, or `*` for every key on the source.
# Prefer naming keys explicitly: it turns "the source grew a key nobody
# reviewed" from a silent copy into a visible skip.
#
# Namespaces are mostly identical on both sides. The ssint-main-* namespaces and
# their Secrets are declared by simplesalt/brain@main, which BOTH clusters
# subscribe to, so those rows are name-for-name by construction.
# --------------------------------------------------------------------------
SECRETS=(
  # -- test subset ---------------------------------------------------------
  # Three low-blast-radius rows to validate the mechanism before widening it.
  # Single-key, unambiguous mapping, and each one's effect is observable.

  # Raw ssint-main Cloudflare API token. A Job wraps it into
  # cloudflare-credentials-main; verify by watching that ProviderConfig go ready.
  'crossplane-system|ssint-main-cf|crossplane-system|ssint-main-cf|api_token'

  # Google OAuth client_id for the SS SSO IdP. A client_id is a public
  # identifier rather than credential material, so it is the safest possible
  # thing to get wrong. Consumed via postBuild.substituteFrom -- confirm the new
  # cluster's top-level Kustomization actually wires that substituteFrom, which
  # lives in bootstrap config outside this repo.
  'flux-system|ssint-main-g-idp-id|flux-system|ssint-main-g-idp-id|client_id'

  # OpenAI key for gbrain's embedding provider. Single consumer, mounted
  # optional:true, so a bad copy degrades embeddings instead of crash-looping.
  'ssint-main-ai|gbrain-embedding-secret|ssint-main-ai|gbrain-embedding-secret|OPENAI_API_KEY'
)

# --------------------------------------------------------------------------
# The rest of the inventory, held back until the three above are proven.
#
# Compiled from the manifests, NOT from the live cluster: the flux MCP's
# ServiceAccount is deliberately denied get/list on Secrets, so no row here --
# including the three active ones -- has been checked against a live object.
# Expect at least one to be absent or to carry a key set that has drifted.
#
# 'crossplane-system|gcp-credentials|crossplane-system|gcp-credentials|credentials'
# 'cert-manager|ss-acme-cf-token|cert-manager|ss-acme-cf-token|api-token'
# 'crossplane-system|ssint-main-g-idp-secret|crossplane-system|ssint-main-g-idp-secret|client_secret'
# 'cert-manager|fe-acme-cf-token|cert-manager|fe-acme-cf-token|api-token'
# 'ssint-main-ai|hermes-secrets|ssint-main-ai|hermes-secrets|*'
# 'ssint-main-ai|team-roster|ssint-main-ai|team-roster|roster.json'
# 'ssint-main-ai|project-tracking|ssint-main-ai|project-tracking|board-config.json'
# 'ssint-main-ai|google-dwd-key|ssint-main-ai|google-dwd-key|*'
# 'ssint-main-msg|google-dwd-key|ssint-main-msg|google-dwd-key|*'
# 'ssint-main-msg|google-private-key-id|ssint-main-msg|google-private-key-id|private_key_id'
# 'ssint-main-msg|duxsoup-api-key|ssint-main-msg|duxsoup-api-key|api_key'
# 'ssint-main-msg|duxsoup-user-id|ssint-main-msg|duxsoup-user-id|user_id'
# 'ssint-main-msg|quo-api-key|ssint-main-msg|quo-api-key|api_key'
# 'ssint-main-msg|quo-from-number|ssint-main-msg|quo-from-number|from_number'
# 'ssint-main-cal|team-roster|ssint-main-cal|team-roster|roster.json'
# 'ssint-main-coding|gh-auth|ssint-main-coding|gh-auth|GITHUB_TOKEN'
# 'ssint-main-coding|cf-secret|ssint-main-coding|cf-secret|CLOUDFLARE_API_TOKEN'
# 'ssint-main-coding|cf-id|ssint-main-coding|cf-id|CLOUDFLARE_ACCOUNT_ID'
# 'ssint-main-coding|claude-identity|ssint-main-coding|claude-identity|*'
#
# Unresolved -- needs a decision before it can get a row:
#   cluster-named-svcs/cnpg-backup-credentials  CNPG R2 backup creds. No
#     equivalent declaration found in any new-cluster repo; either the new
#     cluster's CNPG backup wiring lives somewhere unsearched or it does not
#     exist yet. Target namespace unknown.
#   ssint-main-coding/claude-auth  Declared in brain's coding.yaml and named in
#     its header comment, but no secretKeyRef or volume mount consumes it.
#     Possibly vestigial.
#
# DO NOT COPY -- these break rather than migrate:
#   claude-oauth-{oci,brain,basis}  Anthropic OAuth refresh tokens are
#     single-use/rotating. Two holders of one token invalidate each other on
#     refresh, so copying while the old pods still run breaks both sides. Run
#     `claude /login` on the new pods instead.
#   claude-oauth-base-stack  Its Deployment no longer exists; the placeholder is
#     retained only to stop Flux pruning it.
#   cal-secret, calcom-api-key  Seeded by in-cluster bootstrap Jobs on first
#     deploy, not hand-patched. Let the Jobs re-run.
#   Any cert-manager TLS Secret (famevans-tls-svcs, ai-tls, ...)  Bound to the
#     issuing ClusterIssuer's key and re-issued per cluster.
#   Crossplane writeConnectionSecretToRef outputs (cloudflare-credentials,
#     cloudflare-credentials-main, *-tunnel-token, *-tunnel-id,
#     cloudflare-sso-agent-key)  Derived from an upstream manual Secret or from
#     a live Crossplane object. Copying these points the new cluster at the OLD
#     cluster's tunnel.
#   ServiceAccount tokens, helm.sh/release.v1 Secrets  Cluster-local identity
#     and Helm's own state store.
# --------------------------------------------------------------------------

APPLY=0
FILTERS=()
for arg in "$@"; do
  case "$arg" in
    --apply)   APPLY=1 ;;
    --dry-run) APPLY=0 ;;
    -h|--help) sed -n '2,60p' "$0"; exit 0 ;;
    -*)        echo "unknown flag: $arg" >&2; exit 2 ;;
    *)         FILTERS+=("$arg") ;;
  esac
done

command -v kubectl >/dev/null || { echo "kubectl not found on PATH" >&2; exit 2; }
command -v jq      >/dev/null || { echo "jq not found on PATH" >&2; exit 2; }

: "${OLD_KUBECONFIG:?set OLD_KUBECONFIG to the kubeconfig for the old cluster}"
[[ -r "$OLD_KUBECONFIG" ]] || { echo "cannot read OLD_KUBECONFIG: $OLD_KUBECONFIG" >&2; exit 2; }

OLD=(--kubeconfig "$OLD_KUBECONFIG")
[[ -n "${OLD_CONTEXT:-}" ]] && OLD+=(--context "$OLD_CONTEXT")
NEW=()
[[ -n "${NEW_KUBECONFIG:-}" ]] && NEW+=(--kubeconfig "$NEW_KUBECONFIG")
[[ -n "${NEW_CONTEXT:-}" ]] && NEW+=(--context "$NEW_CONTEXT")

# Preflight. The failure this guards against is both halves resolving to the
# same cluster -- a copy that "succeeds" everywhere and moves nothing, which
# looks identical to a real success in the output. kube-system's UID is stable
# for a cluster's lifetime and differs across two independently bootstrapped
# ones, so it is the cheapest available cluster fingerprint.
old_server=$(kubectl "${OLD[@]}" config view --minify -o jsonpath='{.clusters[0].cluster.server}')
new_server=$(kubectl "${NEW[@]}" config view --minify -o jsonpath='{.clusters[0].cluster.server}')
old_uid=$(kubectl "${OLD[@]}" get ns kube-system -o jsonpath='{.metadata.uid}')
new_uid=$(kubectl "${NEW[@]}" get ns kube-system -o jsonpath='{.metadata.uid}')

echo "FROM (old): $old_server"
echo "TO   (new): $new_server"
if [[ "$old_uid" == "$new_uid" ]]; then
  echo "ABORT: both kubeconfigs resolve to the same cluster (kube-system uid $old_uid)" >&2
  exit 1
fi
if (( APPLY )); then
  echo "mode: APPLY -- will patch Secrets on the new cluster"
else
  echo "mode: dry run -- no writes. Re-run with --apply to patch."
fi
echo

copied=0 skipped=0 failed=0

for record in "${SECRETS[@]}"; do
  IFS='|' read -r old_ns old_name new_ns new_name keys <<< "$record"

  if (( ${#FILTERS[@]} )); then
    match=0
    for f in "${FILTERS[@]}"; do
      [[ "$f" == "$old_name" || "$f" == "$new_name" ]] && match=1
    done
    (( match )) || continue
  fi

  echo "== $old_ns/$old_name  ->  $new_ns/$new_name"

  # Read the source. `|| true` so a missing source is a reported skip rather
  # than an abort under `set -e` that strands the remaining rows.
  src_json=$(kubectl "${OLD[@]}" -n "$old_ns" get secret "$old_name" -o json 2>/dev/null || true)
  if [[ -z "$src_json" ]]; then
    echo "   SKIP: not found on the old cluster"
    (( ++skipped )); continue
  fi

  # Target must exist and must be clean of the last-applied annotation: a merge
  # patch leaves that annotation in place on the RESULT, and the ClusterPolicy
  # denies on the result, so a target already carrying it would reject every
  # write until the annotation is removed.
  dst_json=$(kubectl "${NEW[@]}" -n "$new_ns" get secret "$new_name" -o json 2>/dev/null || true)
  if [[ -z "$dst_json" ]]; then
    echo "   SKIP: not declared on the new cluster (patch cannot create it -- add the placeholder to Git first)"
    src_json=''; unset src_json
    (( ++skipped )); continue
  fi
  if printf '%s' "$dst_json" | jq -e '.metadata.annotations."kubectl.kubernetes.io/last-applied-configuration"' >/dev/null 2>&1; then
    echo "   SKIP: target carries kubectl.kubernetes.io/last-applied-configuration; Kyverno will deny the patch."
    echo "         Remove it first, then re-run:"
    echo "         kubectl -n $new_ns patch secret $new_name --type json \\"
    echo "           -p '[{\"op\":\"remove\",\"path\":\"/metadata/annotations/kubectl.kubernetes.io~1last-applied-configuration\"}]'"
    src_json=''; dst_json=''; unset src_json dst_json
    (( ++failed )); continue
  fi

  src_type=$(printf '%s' "$src_json" | jq -r '.type // "Opaque"')
  dst_type=$(printf '%s' "$dst_json" | jq -r '.type // "Opaque"')
  [[ "$src_type" == "$dst_type" ]] || echo "   NOTE: type differs ($src_type -> $dst_type); patch cannot change .type"

  # Resolve the key list, then report each key's disposition. Key NAMES are
  # printed; values never are. `missing` is a source-side gap -- a key this
  # script names that the old Secret does not have.
  mapfile -t want < <(printf '%s' "$src_json" | jq -r --arg k "$keys" \
    'if $k == "*" then (.data // {} | keys_unsorted[]) else ($k | split(",")[]) end')
  missing=()
  for k in "${want[@]}"; do
    printf '%s' "$src_json" | jq -e --arg k "$k" '.data | has($k)' >/dev/null 2>&1 || missing+=("$k")
  done
  if (( ${#missing[@]} )); then
    echo "   SKIP: key(s) absent on the source: ${missing[*]}"
    src_json=''; dst_json=''; unset src_json dst_json
    (( ++failed )); continue
  fi

  changes=0
  for k in "${want[@]}"; do
    sv=$(printf '%s' "$src_json" | jq -r --arg k "$k" '.data[$k]')
    dv=$(printf '%s' "$dst_json" | jq -r --arg k "$k" '.data[$k] // ""')
    if [[ -z "$dv" ]]; then
      echo "   $k: absent on target -> will set"; (( ++changes ))
    elif [[ "$sv" == "$dv" ]]; then
      echo "   $k: already identical -> no-op"
    else
      echo "   $k: DIFFERS on target -> will overwrite (if the target was rotated more recently, this regresses it)"
      (( ++changes ))
    fi
    sv=''; dv=''; unset sv dv
  done

  if (( ! APPLY )); then
    echo "   dry run: $changes key(s) would change"
    src_json=''; dst_json=''; unset src_json dst_json
    continue
  fi
  if (( changes == 0 )); then
    echo "   nothing to do"
    src_json=''; dst_json=''; unset src_json dst_json
    (( ++skipped )); continue
  fi

  # Build {"data":{...}} over exactly the named keys, and hand it to kubectl on
  # stdin. jq's input is a pipe, kubectl's patch is a pipe, so the payload is
  # never an argv entry and never a file.
  patch=$(printf '%s' "$src_json" | jq -c --arg k "$keys" \
    '.data as $d
     | (if $k == "*" then ($d | keys_unsorted) else ($k | split(",")) end) as $want
     | {data: ($want | map({(.): $d[.]}) | add)}')

  if printf '%s' "$patch" | kubectl "${NEW[@]}" -n "$new_ns" patch secret "$new_name" \
       --type merge --patch-file /dev/stdin >/dev/null; then

    # Verify by reading the target back and comparing the named keys against the
    # source. Compared in-shell, so the result is a yes/no and no digest or
    # value reaches the terminal.
    chk_json=$(kubectl "${NEW[@]}" -n "$new_ns" get secret "$new_name" -o json)
    a=$(printf '%s' "$src_json" | jq -S -c --arg k "$keys" \
      '.data as $d | (if $k == "*" then ($d|keys_unsorted) else ($k|split(",")) end) | map({(.): $d[.]}) | add')
    b=$(printf '%s' "$chk_json" | jq -S -c --arg k "$keys" \
      '.data as $d | (if $k == "*" then ($d|keys_unsorted) else ($k|split(",")) end) | map({(.): $d[.]}) | add')
    if [[ "$a" == "$b" ]]; then
      echo "   OK: patched and verified ($changes key(s))"
      (( ++copied ))
    else
      echo "   FAIL: patch reported success but the target does not match the source"
      (( ++failed ))
    fi
    a=''; b=''; chk_json=''; unset a b chk_json
  else
    echo "   FAIL: patch rejected (RBAC denies create/update -- confirm the target exists and you hold patch)"
    (( ++failed ))
  fi

  patch=''; src_json=''; dst_json=''; unset patch src_json dst_json
done

echo
echo "copied=$copied skipped=$skipped failed=$failed"
(( failed == 0 ))
