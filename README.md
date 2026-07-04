# devedge-idp

A **development-only OpenID Provider (OIDC)** for the devedge ecosystem. It is
the keystone (P0) of the WS-026 dev security suite.

> **NON-PRODUCTION.** Passwordless login, guessable dummy client secrets, and
> in-memory state that resets on restart. Never deploy this outside a
> development environment.

## The two-tier token model

devedge-idp is the **"who you are"** tier. It authenticates a developer
**passwordlessly** and issues a signed **identity assertion** (`id_token`). It
does **not** mint app API bearer tokens, and it does **not** author in-app
roles, tenant, or scopes. A separate **"app identity"** (built later in
devedge-sdk) performs the OIDC dance with this IdP and mints the real app bearer
token, authoring the rich app-specific claims itself.

**Coarse-claims rule (WS-026 D11).** The `id_token` carries **only** coarse
claims: identity plus an app-access entitlement — `sub`, `name`, optional
`email`, and `apps` (a JSON array of app/client names this identity may enter).
It deliberately does **not** carry `tenant`, `roles`, `groups`, `permissions`,
or `scopes`; those are authored downstream by the app identity. (The IdP may
*store* a richer profile per identity for future use, but it never *emits* it.)

## Built on devedge-sdk

The process runs on the devedge-sdk server harness (`server.New(...).Serve`),
not a bare `http.ListenAndServe`. The zitadel OP handler and the login page are
mounted through the SDK's `server.Config.HTTPHandlers` seam (the OP claims `/`;
the login page claims the more specific `/login`). This dogfoods the SDK.

## Run it

```sh
go run ./cmd/idp
# or with explicit addresses / a pinned issuer:
IDP_HTTP_ADDR=:8080 IDP_GRPC_ADDR=:9090 IDP_ISSUER=http://idp.dev.test go run ./cmd/idp
```

Flags mirror the env vars: `-http-addr`, `-grpc-addr`, `-issuer`. When `-issuer`
is empty the issuer is derived per-request from the `Host` header (handy on
ephemeral ports).

### URLs served (on the HTTP port)

| Path | Purpose |
|------|---------|
| `/.well-known/openid-configuration` | OIDC discovery |
| `/authorize` | authorization endpoint (auth-code + PKCE S256) |
| `/oauth/token` | token endpoint (auth-code + refresh + device grants) |
| `/keys` | JWKS (id_token signing public keys) |
| `/device_authorization` | device grant (RFC 8628) |
| `/login` | passwordless identity picker (interactive + headless) |
| `/healthz`, `/readyz` | SDK liveness / readiness probes |

## Built-in identities (passwordless dev fixtures)

Edit them in one place: `internal/idp/identities.go` (`var Identities`).

| Subject | Name | Apps |
|---------|------|------|
| `alice` | Alice Admin | all seeded apps |
| `bob` | Bob Viewer | all seeded apps |
| `carol` | Carol (tenant-b) | all seeded apps |

"Login" is picking one — no credential is checked. For automation, complete the
flow headlessly: `GET /login?authRequestID=<id>&identity=alice`.

## Seeded client (an "app identity")

An in-memory confidential client, edit in `internal/idp/clients.go`:

- `client_id`: `devedge-idp-example`
- `client_secret`: `dev-secret` (guessable, dev-only)
- grants: authorization_code (PKCE), refresh_token, device_code

Register more clients at runtime via `Storage.RegisterClient` — the seam the
future `de idp clients sync` will use.

## Acceptance test

`cmd/idp/acceptance_test.go` boots the IdP through the real
`server.New(...).Serve` path and, with no browser, drives a full
confidential-client **auth-code + PKCE** round-trip, then verifies the returned
`id_token` against the served JWKS and asserts the coarse-claims rule.

```sh
go build ./... && go test ./...
```
