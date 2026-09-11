#!/usr/bin/env bash
#
# ShipStampede Customer API — mint a service-user access token.
#
# Every Customer API call is authenticated with a short-lived bearer
# token. This script performs the one exchange that produces it: it
# signs an HMAC envelope with your service-user secret and POSTs it to
# the token endpoint. The secret itself never crosses the wire.
#
# Requires bash, curl and openssl. `jq` is optional — without it the
# response is printed unformatted.
#
# ── Before you start ───────────────────────────────────────────────
#
# You need two credentials, created at https://app.shipstampede.com →
# Settings › Service Users › New:
#
#   Key ID   "svc_" followed by 32 hex characters — safe to share
#   Secret   64 hex characters — shown ONCE, at creation time
#
# The secret is never recoverable. If it is lost, use "Regenerate
# secret" on the same screen; that invalidates the previous one
# immediately. Scopes are picked at creation and can be edited later —
# a token is only ever as broad as the scopes on its key.
#
# ── The API base URL ───────────────────────────────────────────────
#
# This public copy ships with the endpoint as a placeholder. Set
# SS_API_URL (or pass --url) to the token endpoint ShipStampede gave
# you; the script refuses to run until you do.
#
# ── Quick start ────────────────────────────────────────────────────
#
#   export SS_API_URL=https://.../v1/auth/tokens
#   export SS_KEY_ID=svc_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
#   export SS_SECRET=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx...
#   ./service-auth-token.sh
#
# Capture just the token and use it:
#
#   TOKEN="$(./service-auth-token.sh --token-only)"
#   curl -sS https://<shipstampede-api-host>/v1/rating/rates \
#     -H "Authorization: Bearer $TOKEN"
#
# ── Options ────────────────────────────────────────────────────────
#
#   --key-id      Service key id      (env: SS_KEY_ID)
#   --secret      Plaintext secret    (env: SS_SECRET)
#   --url         Token endpoint      (env: SS_API_URL)
#                 REQUIRED — see "The API base URL" above
#   --token-only  Print only the access token
#   --raw         Print the full JSON response (default)
#   --verbose     Echo the signed envelope to stderr
#
# ── What comes back ────────────────────────────────────────────────
#
#   {
#     "user":        { "id": "...", "email": "...", "accountId": "..." },
#     "permissions": ["rating:rates:get", "shipping:label:generate"],
#     "tokens":      { "accessToken": "eyJ..." }
#   }
#
# "permissions" is the effective scope list for the key and is the
# quickest way to explain a 403 on an otherwise valid call. Send the
# token as "Authorization: Bearer <accessToken>" on every Customer API
# request. Tokens last about 15 minutes and there is NO refresh token —
# re-run this exchange, which is cheap, rather than trying to extend one.
#
# ── The signature, if you are porting this ─────────────────────────
#
#   canonical = "<ts>\n<nonce>\n<sha256_hex(body)>"
#   signature = hex(hmac_sha256(secret, canonical))
#
# The token endpoint carries no inner payload, so the body is "" and the
# hash is sha256(""). The server recomputes this exact string, so:
#
#   ts         unix SECONDS (not milliseconds), within ±5 minutes of
#              server time
#   nonce      16–128 characters, unique per request — each one is
#              accepted exactly once per key
#   signature  lowercase hex, 64 characters
#
# ── If you get 401 INVALID_CREDENTIALS ─────────────────────────────
#
# Signature mismatch, clock skew, replay, unknown key, disabled key and
# expired key all return that single code deliberately, so nothing can
# be probed from the outside. Work down the list:
#
#   1. Clock skew — ts is more than 5 minutes from server time. The most
#      common cause on a container or VM. Compare "date -u".
#   2. Reused nonce — generate a fresh one per attempt, never hard-code
#      one, and do not retry a failed request with the same envelope.
#   3. Wrong URL — log the URL your client actually sends and compare
#      it character for character with the one ShipStampede gave you.
#      A base-path join or a proxy rewrite that alters it will never
#      reach the endpoint.
#   4. Milliseconds in ts, or an uppercase signature.
#   5. Key disabled, deleted, past its expiration, or the service user
#      deactivated — check Settings › Service Users.
#   6. Stale secret — a regenerate invalidates the old one at once.
#
# Point --url (or SS_API_URL) only at an environment you have been
# given credentials for. A key issued in one environment never
# authenticates against another.
set -euo pipefail

# Public copy: the endpoint is a placeholder, supplied via SS_API_URL/--url.
TOKEN_ENDPOINT_PLACEHOLDER='https://<shipstampede-api-host>/v1/auth/tokens'
API_URL="${SS_API_URL:-$TOKEN_ENDPOINT_PLACEHOLDER}"
KEY_ID="${SS_KEY_ID:-}"
SECRET="${SS_SECRET:-}"
OUTPUT="raw"
VERBOSE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --key-id)     KEY_ID="$2"; shift 2 ;;
    --secret)     SECRET="$2"; shift 2 ;;
    --url)        API_URL="$2"; shift 2 ;;
    --token-only) OUTPUT="token"; shift ;;
    --raw)        OUTPUT="raw"; shift ;;
    --verbose)    VERBOSE=1; shift ;;
    # Prints the guide at the top of this file, so the two never drift.
    -h|--help)    awk 'NR>1 && /^#/ { sub(/^# ?/, ""); print; next } NR>1 { exit }' "$0"; exit 0 ;;
    *)            echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "$KEY_ID" || -z "$SECRET" ]]; then
  echo "error: --key-id/SS_KEY_ID and --secret/SS_SECRET are required" >&2
  exit 2
fi

if [[ "$API_URL" == "$TOKEN_ENDPOINT_PLACEHOLDER" ]]; then
  echo "error: set --url/SS_API_URL to the token endpoint ShipStampede gave you" >&2
  exit 2
fi

for bin in openssl curl; do
  command -v "$bin" >/dev/null || { echo "error: $bin not found on PATH" >&2; exit 1; }
done

TS="$(date -u +%s)"

# 32 hex chars — satisfies the 16..128 length bound on `nonce` and is
# unique per request, which is what the (keyId, nonce) replay table dedups on.
NONCE="$(openssl rand -hex 16)"

# The endpoint takes no signed payload; the canonical string ends with the
# hash of the empty string.
BODY=""
BODY_HASH="$(printf '%s' "$BODY" | openssl dgst -sha256 | awk '{print $NF}')"

CANONICAL="$(printf '%s\n%s\n%s' "$TS" "$NONCE" "$BODY_HASH")"
SIGNATURE="$(printf '%s' "$CANONICAL" \
  | openssl dgst -sha256 -hmac "$SECRET" \
  | awk '{print $NF}')"

if [[ "$VERBOSE" -eq 1 ]]; then
  {
    echo "POST ${API_URL}"
    echo "keyId=${KEY_ID} ts=${TS} nonce=${NONCE}"
    echo "canonical=$(printf '%s' "$CANONICAL" | sed 's/$/\\n/' | tr -d '\n')"
    echo "signature=${SIGNATURE}"
  } >&2
fi

PAYLOAD="$(printf '{"keyId":"%s","ts":%s,"nonce":"%s","signature":"%s"}' \
  "$KEY_ID" "$TS" "$NONCE" "$SIGNATURE")"

RESPONSE="$(curl -4 -sS -X POST "${API_URL}" \
  -H 'Content-Type: application/json' \
  -w $'\n%{http_code}' \
  -d "$PAYLOAD")"

STATUS="${RESPONSE##*$'\n'}"
BODY_OUT="${RESPONSE%$'\n'*}"

if [[ "$STATUS" != "200" ]]; then
  echo "error: token request failed (HTTP ${STATUS})" >&2
  echo "$BODY_OUT" >&2
  exit 1
fi

if [[ "$OUTPUT" == "token" ]]; then
  if command -v jq >/dev/null; then
    printf '%s' "$BODY_OUT" | jq -r '.tokens.accessToken'
  else
    printf '%s' "$BODY_OUT" \
      | sed -n 's/.*"accessToken"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p'
  fi
else
  if command -v jq >/dev/null; then
    printf '%s' "$BODY_OUT" | jq .
  else
    printf '%s\n' "$BODY_OUT"
  fi
fi
