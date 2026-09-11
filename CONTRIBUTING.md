# Maintaining this repository

Notes for ShipStampede engineers. Partners should start at the [README](README.md).

## This is a derived artifact

The scripts here are **copies**. The source of truth is `scripts/service-auth-token.{mjs,sh}`
in the platform monorepo, which is where they are tested against real endpoints
and reviewed. Fix things there first, then port the change here.

Editing only this copy means the next port silently reverts you.

## The endpoint is always a placeholder

This repository is public. The public copies carry:

```
https://<shipstampede-api-host>/v1/auth/tokens
```

and a guard that refuses to run until `SS_API_URL` (or `--url`) is set. The
internal copies default to the real production endpoint instead — that is the
one intended difference between the two, and the only one that matters.

`.github/workflows/leak-check.yml` fails the build if a real API host is
committed. It is the backstop for the one mistake that is otherwise silent: a
careless re-copy from the monorepo republishing the endpoint. Do not weaken it.

The dashboard host (`app.shipstampede.com`) is fine — it is not an API endpoint.

## When to sync

Only when the authentication contract actually changes. The watch list:

| File (platform monorepo) | What it governs |
|---|---|
| `packages/iac/core/src/use-cases/auth/ServiceAuthTokenUsecase.ts` | canonical string, ±5 min skew window, replay/nonce semantics, token lifetime |
| `packages/iac/dtos/src/requests.ts` | `ServiceAuthTokenRequest` field bounds |
| `apps/backend-api/src/modules/iac/useServiceAuthRoutes.ts` | the route and its error contract |

If none of those moved, this repository does not need touching.

## Porting a change

1. Land the fix in the monorepo.
2. Copy the file here and re-apply the placeholder edits: the default URL
   constant, the guard block, the `curl` example, the options table, the
   "wrong URL" troubleshooting item, and the closing paragraph.
3. Run both scripts once with `SS_API_URL` set to confirm they still work, and
   once without to confirm the guard fires.
4. Open a PR. The leak check runs on push and pull request.

The `--help` output of each script is generated from its own header comment, so
the guide and the flag cannot drift from each other — you only need to keep the
header correct.

## Partner-facing consequences

Changing anything here changes what partners already have. Existing integrations
copied an earlier version, so a change to the signing rules is a breaking change
for them and needs an email, not just a commit.
