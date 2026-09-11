# ShipStampede API examples

Reference clients for authenticating against the ShipStampede Customer API.

Every Customer API call is authenticated with a short-lived bearer token. These
scripts perform the one exchange that produces it: they sign an HMAC envelope
with your service-user secret and POST it to the token endpoint. **The secret
itself never crosses the wire.**

| File | Requirements |
|---|---|
| [`service-auth-token.mjs`](service-auth-token.mjs) | Node 18+ (built-in `fetch`) |
| [`service-auth-token.sh`](service-auth-token.sh) | `bash`, `curl`, `openssl` (`jq` optional) |

Both are standalone — no install step, no dependencies. Each carries a full
guide in its header; run either with `-h` to read it.

## What you need

Three values:

| Value | Where it comes from |
|---|---|
| **API base URL** | Your ShipStampede contact. These public copies ship with a placeholder, so `SS_API_URL` is required — the scripts stop and tell you if it is unset. |
| **Key ID** | `svc_` followed by 32 hex characters. Safe to share. |
| **Secret** | 64 hex characters. Shown **once**, at creation. |

Create a service user at **Settings › Service Users › New** in the ShipStampede
dashboard. The secret is never recoverable afterwards — if it is lost, either
use **Regenerate secret** (which invalidates the previous one immediately) or
create another service user. You can have as many as you need.

## Usage

```bash
export SS_API_URL=https://.../v1/auth/tokens   # the endpoint you were given
export SS_KEY_ID=svc_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
export SS_SECRET=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx...

node service-auth-token.mjs          # or: ./service-auth-token.sh
```

Capture just the token and use it:

```bash
TOKEN="$(node service-auth-token.mjs --token-only)"
curl -sS "$SS_API_BASE/rating/rates" -H "Authorization: Bearer $TOKEN"
```

### Options

| Flag | Env | Meaning |
|---|---|---|
| `--key-id` | `SS_KEY_ID` | Service key id |
| `--secret` | `SS_SECRET` | Plaintext secret |
| `--url` | `SS_API_URL` | Token endpoint (required) |
| `--token-only` | | Print only the access token |
| `--verbose` | | Echo the signed envelope to stderr |

## What comes back

```json
{
  "user":        { "id": "...", "email": "...", "accountId": "..." },
  "permissions": ["rating:rates:get", "shipping:label:generate"],
  "tokens":      { "accessToken": "eyJ..." }
}
```

`permissions` is the effective scope list for the key — the quickest way to
explain a `403` on an otherwise valid call. Scopes are set on the key, so a
valid token is only ever as broad as its key.

Send the token as `Authorization: Bearer <accessToken>` on every request.
Tokens last about 15 minutes and there is **no refresh token** — clients
re-sign, which is cheap.

## The signature

```
canonical = ts + "\n" + nonce + "\n" + sha256_hex(body)
signature = hex(hmac_sha256(secret, canonical))
```

The token endpoint carries no inner payload, so `body` is `""` and the hash is
`sha256("")`. The server recomputes this exact string, so when porting to
another language:

- **`ts`** — unix **seconds** (not milliseconds), within ±5 minutes of server time
- **`nonce`** — 16–128 characters, unique per request; each is accepted exactly once per key
- **`signature`** — lowercase hex, 64 characters

## Troubleshooting `401 INVALID_CREDENTIALS`

Signature mismatch, clock skew, replay, unknown key, disabled key and expired
key all return that single code deliberately, so nothing can be probed from the
outside. Work down the list:

1. **Clock skew** — `ts` more than 5 minutes from server time. The most common
   cause on a container or VM. Compare `date -u`.
2. **Reused nonce** — generate a fresh one per attempt, never hard-code one, and
   do not retry a failed request with the same envelope.
3. **Wrong URL** — log the URL your client actually sends and compare it
   character for character with the one you were given.
4. **Milliseconds in `ts`**, or an uppercase signature.
5. **Key disabled, deleted, past its expiration**, or the service user
   deactivated.
6. **Stale secret** — a regenerate invalidates the old one at once.

A `403` instead means the key authenticated but lacks the scope for that
endpoint — check the `permissions` array.

## Support

Contact your ShipStampede representative. When reporting an auth problem,
include your **Key ID**, the `ts`, `nonce` and `signature` you sent, the full
URL, and the time of the attempt.

**Never send your secret** — it is not needed to diagnose anything.
