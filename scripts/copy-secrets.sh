#!/usr/bin/env bash

set -euo pipefail

case "$-" in
  *x*) echo "refusing to run under 'set -x': tracing would echo secret payloads" >&2; exit 2 ;;
esac
umask 077

SECRETS=(

  'crossplane-system|ssint-main-cf|crossplane-system|ssint-main-cf|api_token,CLOUDFLARE_ACCOUNT_ID'

  'flux-system|ssint-main-g-idp-id|flux-system|ssint-main-g-idp-id|client_id'

  'ssint-main-ai|gbrain-embedding-secret|ssint-main-ai|gbrain-embedding-secret|OPENAI_API_KEY'
  'crossplane-system|gcp-credentials|crossplane-system|gcp-credentials|credentials,sa_key'
  'cert-manager|ss-acme-cf-token|cert-manager|ss-acme-cf-token|api-token'
  'crossplane-system|ssint-main-g-idp-secret|crossplane-system|ssint-main-g-idp-secret|client_secret'
  'cert-manager|fe-acme-cf-token|cert-manager|fe-acme-cf-token|api-token'
  'ssint-main-ai|hermes-secrets|ssint-main-ai|hermes-secrets|CLOUDFLARE_ACCOUNT_ID,CLOUDFLARE_API_TOKEN,FIRECRAWL_API_KEY,GENERAL_API_LLM_API_KEY,GITHUB_TOKEN,GOOGLE_CLIENT_ID,GOOGLE_PRIVATE_KEY_B64,GOOGLE_PRIVATE_KEY_ID,HERMES_BEARER_TOKEN,HERMES_WEBHOOK_HMAC_KEY,HINDSIGHT_API_LLM_API_KEY,TAVILY_API_KEY,WORK_EMAIL'
  'ssint-main-ai|team-roster|ssint-main-ai|team-roster|roster.json'
  'ssint-main-ai|project-tracking|ssint-main-ai|project-tracking|board-config.json'
  'ssint-main-ai|google-dwd-key|ssint-main-ai|google-dwd-key|*'
  'ssint-main-msg|google-dwd-key|ssint-main-msg|google-dwd-key|*'
  'ssint-main-msg|google-private-key-id|ssint-main-msg|google-private-key-id|private_key_id'
  'ssint-main-msg|duxsoup-api-key|ssint-main-msg|duxsoup-api-key|api_key'
  'ssint-main-msg|duxsoup-user-id|ssint-main-msg|duxsoup-user-id|user_id'
  'ssint-main-msg|quo-api-key|ssint-main-msg|quo-api-key|api_key'
  'ssint-main-msg|quo-from-number|ssint-main-msg|quo-from-number|from_number'
  'ssint-main-cal|team-roster|ssint-main-cal|team-roster|roster.json'
  'ssint-main-coding|gh-auth|ssint-main-coding|gh-auth|GITHUB_TOKEN'
  'ssint-main-coding|cf-secret|ssint-main-coding|cf-secret|CLOUDFLARE_API_TOKEN'
  'ssint-main-coding|cf-id|ssint-main-coding|cf-id|CLOUDFLARE_ACCOUNT_ID'
  'ssint-main-coding|claude-identity|ssint-main-coding|claude-identity|*'
)


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

  src_json=$(kubectl "${OLD[@]}" -n "$old_ns" get secret "$old_name" -o json 2>/dev/null || true)
  if [[ -z "$src_json" ]]; then
    echo "   SKIP: not found on the old cluster"
    (( ++skipped )); continue
  fi

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

  patch=$(printf '%s' "$src_json" | jq -c --arg k "$keys" \
    '.data as $d
     | (if $k == "*" then ($d | keys_unsorted) else ($k | split(",")) end) as $want
     | {data: ($want | map({(.): $d[.]}) | add)}')

  if printf '%s' "$patch" | kubectl "${NEW[@]}" -n "$new_ns" patch secret "$new_name" \
       --type merge --patch-file /dev/stdin >/dev/null; then

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
