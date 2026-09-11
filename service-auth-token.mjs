#!/usr/bin/env node
/**
 * ShipStampede Customer API — mint a service-user access token.
 *
 * Every Customer API call is authenticated with a short-lived bearer
 * token. This script performs the one exchange that produces it: it
 * signs an HMAC envelope with your service-user secret and POSTs it to
 * the token endpoint. The secret itself never crosses the wire.
 *
 * Requires Node 18+ (uses the built-in fetch).
 *
 * ── Before you start ───────────────────────────────────────────────
 *
 * You need two credentials, created at https://app.shipstampede.com →
 * Settings → Service Users → New:
 *
 *   Key ID   `svc_` followed by 32 hex characters — safe to share
 *   Secret   64 hex characters — shown ONCE, at creation time
 *
 * The secret is never recoverable. If it is lost, use "Regenerate
 * secret" on the same screen; that invalidates the previous one
 * immediately. Scopes are picked at creation and can be edited later —
 * a token is only ever as broad as the scopes on its key.
 *
 * ── The API base URL ───────────────────────────────────────────────
 *
 * This public copy ships with the endpoint as a placeholder. Set
 * SS_API_URL (or pass --url) to the token endpoint ShipStampede gave
 * you; the script refuses to run until you do.
 *
 * ── Quick start ────────────────────────────────────────────────────
 *
 *   export SS_API_URL=https://.../v1/auth/tokens
 *   export SS_KEY_ID=svc_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
 *   export SS_SECRET=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx...
 *   node service-auth-token.mjs
 *
 * Capture just the token and use it:
 *
 *   TOKEN=$(node service-auth-token.mjs --token-only)
 *   curl -sS https://<shipstampede-api-host>/v1/rating/rates \
 *     -H "Authorization: Bearer $TOKEN"
 *
 * ── Options ────────────────────────────────────────────────────────
 *
 *   --key-id      Service key id      (env: SS_KEY_ID)
 *   --secret      Plaintext secret    (env: SS_SECRET)
 *   --url         Token endpoint      (env: SS_API_URL)
 *                 REQUIRED — see "The API base URL" above
 *   --token-only  Print only the access token
 *   --verbose     Echo the signed envelope to stderr
 *
 * ── What comes back ────────────────────────────────────────────────
 *
 *   {
 *     "user":        { "id": "...", "email": "...", "accountId": "..." },
 *     "permissions": ["rating:rates:get", "shipping:label:generate"],
 *     "tokens":      { "accessToken": "eyJ..." }
 *   }
 *
 * `permissions` is the effective scope list for the key and is the
 * quickest way to explain a 403 on an otherwise valid call. Send the
 * token as `Authorization: Bearer <accessToken>` on every Customer API
 * request. Tokens last about 15 minutes and there is NO refresh token —
 * re-run this exchange, which is cheap, rather than trying to extend one.
 *
 * ── The signature, if you are porting this ─────────────────────────
 *
 *   canonical = `${ts}\n${nonce}\n${sha256_hex(body)}`
 *   signature = hex(hmac_sha256(secret, canonical))
 *
 * The token endpoint carries no inner payload, so `body` is '' and the
 * hash is sha256(""). The server recomputes this exact string, so:
 *
 *   ts         unix SECONDS (not milliseconds), within ±5 minutes of
 *              server time
 *   nonce      16–128 characters, unique per request — each one is
 *              accepted exactly once per key
 *   signature  lowercase hex, 64 characters
 *
 * ── If you get 401 INVALID_CREDENTIALS ─────────────────────────────
 *
 * Signature mismatch, clock skew, replay, unknown key, disabled key and
 * expired key all return that single code deliberately, so nothing can
 * be probed from the outside. Work down the list:
 *
 *   1. Clock skew — `ts` is more than 5 minutes from server time. The
 *      most common cause on a container or VM. Compare `date -u`.
 *   2. Reused nonce — generate a fresh one per attempt, never hard-code
 *      one, and do not retry a failed request with the same envelope.
 *   3. Wrong URL — log the URL your client actually sends and compare
 *      it character for character with the one ShipStampede gave you.
 *      A base-path join or a proxy rewrite that alters it will never
 *      reach the endpoint.
 *   4. Milliseconds in `ts`, or an uppercase signature.
 *   5. Key disabled, deleted, past its expiration, or the service user
 *      deactivated — check Settings → Service Users.
 *   6. Stale secret — a regenerate invalidates the old one at once.
 *
 * Point --url (or SS_API_URL) only at an environment you have been
 * given credentials for. A key issued in one environment never
 * authenticates against another.
 */
import { readFileSync } from 'node:fs';
import { createHash, createHmac, randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';

// Public copy: the endpoint is a placeholder, supplied via SS_API_URL/--url.
const TOKEN_ENDPOINT_PLACEHOLDER = 'https://<shipstampede-api-host>/v1/auth/tokens';

// `--help` prints the guide at the top of this file, so the two never
// drift apart.
function printHelp() {
  const source = readFileSync(fileURLToPath(import.meta.url), 'utf8');
  const block = source.slice(source.indexOf('/**') + 3, source.indexOf('*/'));
  console.log(block.replace(/^[ \t]*\* ?/gm, '').trim());
}

function parseArgs(argv) {
  const opts = {
    keyId: process.env.SS_KEY_ID ?? '',
    secret: process.env.SS_SECRET ?? '',
    url: process.env.SS_API_URL ?? TOKEN_ENDPOINT_PLACEHOLDER,
    tokenOnly: false,
    verbose: false,
  };
  for (let i = 0; i < argv.length; i++) {
    switch (argv[i]) {
      case '--key-id':
        opts.keyId = argv[++i];
        break;
      case '--secret':
        opts.secret = argv[++i];
        break;
      case '--url':
        opts.url = argv[++i];
        break;
      case '--token-only':
        opts.tokenOnly = true;
        break;
      case '--verbose':
        opts.verbose = true;
        break;
      case '-h':
      case '--help':
        printHelp();
        process.exit(0);
        break;
      default:
        console.error(`unknown argument: ${argv[i]}`);
        process.exit(2);
    }
  }
  return opts;
}

/**
 * Signs the canonical envelope the server recomputes in
 * ServiceAuthTokenUsecase. `body` is '' for the token endpoint.
 */
export function signEnvelope({ ts, nonce, body = '', secret }) {
  const canonical = `${ts}\n${nonce}\n${createHash('sha256').update(body).digest('hex')}`;
  return createHmac('sha256', secret).update(canonical).digest('hex');
}

export async function requestServiceToken({ endpoint, keyId, secret, verbose = false }) {
  const ts = Math.floor(Date.now() / 1000);
  // 32 hex chars — inside the 16..128 bound on `nonce`, and unique per
  // request, which is what the (keyId, nonce) replay table dedups on.
  const nonce = randomBytes(16).toString('hex');
  const signature = signEnvelope({ ts, nonce, body: '', secret });

  if (verbose) {
    console.error(`POST ${endpoint}`);
    console.error(`keyId=${keyId} ts=${ts} nonce=${nonce}`);
    console.error(`signature=${signature}`);
  }

  const response = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ keyId, ts, nonce, signature }),
  });

  const text = await response.text();
  if (!response.ok) {
    throw new Error(`token request failed (HTTP ${response.status}): ${text}`);
  }
  return JSON.parse(text);
}

const isMain = import.meta.url === `file://${process.argv[1]}`;
if (isMain) {
  const opts = parseArgs(process.argv.slice(2));
  if (!opts.keyId || !opts.secret) {
    console.error('error: --key-id/SS_KEY_ID and --secret/SS_SECRET are required');
    process.exit(2);
  }
  if (opts.url === TOKEN_ENDPOINT_PLACEHOLDER) {
    console.error(
      'error: set --url/SS_API_URL to the token endpoint ShipStampede gave you'
    );
    process.exit(2);
  }

  try {
    const result = await requestServiceToken({
      endpoint: opts.url,
      keyId: opts.keyId,
      secret: opts.secret,
      verbose: opts.verbose,
    });
    console.log(
      opts.tokenOnly ? result.tokens.accessToken : JSON.stringify(result, null, 2)
    );
  } catch (error) {
    console.error(`error: ${error instanceof Error ? error.message : error}`);
    process.exit(1);
  }
}
