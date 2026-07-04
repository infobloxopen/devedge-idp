# devedge-idp

The **dev security suite** for the devedge ecosystem (WS-026), built on
devedge-sdk. It has two halves behind two SDK seams:

- **Identity** — a development-only **OpenID Provider** (`cmd/idp`): who you are.
  It authenticates passwordlessly and issues a signed identity assertion.
- **Decisions** — a development-only **dev authz service** (`cmd/devauthz`): what
  you may do. It answers `POST /v1/authorize` behind the `authz.Authorizer` seam
  and its grants are manipulable **live** — edit a file or `PUT` new grants and a
  decision flips with no restart.

A microservice built on devedge-sdk wires the IdP-derived bearer into its
`Authenticator` (verify) and the dev authz service into its `Authorizer`
(decide); `e2e/verifydecide_test.go` proves the full VERIFY→DECIDE pipeline
headlessly, including a live grant flip.

> **NON-PRODUCTION.** Passwordless login, guessable dummy client secrets,
> unauthenticated admin endpoints, and in-memory state that resets on restart.
> Never deploy either binary outside a development environment.

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
# or with explicit addresses / a pinned issuer / a hot-reloadable clients file:
IDP_HTTP_ADDR=:8080 IDP_GRPC_ADDR=:9090 IDP_ISSUER=http://idp.dev.test \
  IDP_CLIENTS=./idp-clients.json go run ./cmd/idp
```

Flags mirror the env vars: `-http-addr`, `-grpc-addr`, `-issuer`, `-clients`.
When `-issuer` is empty the issuer is derived per-request from the `Host` header
(handy on ephemeral ports). `-clients` is optional (see the client registry
below); when unset only the seeded client is registered.

Open `http://localhost:8080/` in a browser to see the launchpad.

### URLs served (on the HTTP port)

| Path | Purpose |
|------|---------|
| `/` | launchpad (SSO session) or identity picker (no session) |
| `/pick?identity=<sub>` | establish the IdP SSO session for a built-in identity |
| `/logout` | clear the IdP SSO session (back to the picker) |
| `/switch` | switch user (logout + pick another) |
| `/launchpad.json` | the launchpad model (session, identities, tiles) as JSON |
| `/ui/launchpad.js` | the launchpad frontend bundle (built on devedge-ufe-sdk) |
| `/.well-known/openid-configuration` | OIDC discovery |
| `/authorize` | authorization endpoint (auth-code + PKCE S256) |
| `/oauth/token` | token endpoint (auth-code + refresh + device grants) |
| `/keys` | JWKS (id_token signing public keys) |
| `/device_authorization` | device grant (RFC 8628) |
| `/login` | passwordless identity picker mid-`/authorize` (interactive + headless) |
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

## Client registry (the "app identities")

An in-memory confidential client is always seeded (edit in
`internal/idp/clients.go`):

- `client_id`: `devedge-idp-example`
- `client_secret`: `dev-secret` (guessable, dev-only)
- grants: authorization_code (PKCE), refresh_token, device_code

### Hot-reloadable clients file

Point `-clients` / `IDP_CLIENTS` at an `idp-clients.json` to register more
clients. The file **augments** the seeded set (the seeded client always stays,
so the acceptance tests keep working) and is **hot-reloaded**: the IdP polls the
file's mtime every second and re-registers clients + refreshes the launchpad
tiles on change — edit the file and a new app tile appears with **no restart**.
A bad/parse-error edit keeps the last-good set (it never crashes the IdP). This
is the file a sibling `de idp clients sync` writes. The exact shape (see the
sample `idp-clients.json`):

```json
[
  {
    "client_id": "orders",
    "client_secret": "dev-secret-orders",
    "redirect_uris": ["https://orders.app.dev.test/callback"],
    "tile": { "name": "Orders", "description": "", "icon_url": "", "launch_url": "https://orders.app.dev.test/" }
  }
]
```

The `tile` metadata drives the launchpad. Clients can also be registered
programmatically via `Storage.RegisterClient` / `Storage.ReplaceFileClients`.

## Launchpad + identity picker

The IdP serves its own UI through the SDK `HTTPHandlers` mount seam:

- **Identity picker** (`/` with no SSO session) — lists the built-in identities;
  picking one (`/pick?identity=<sub>`) sets the IdP-owned SSO session cookie
  (`idp_session`) and lands on the launchpad. Passwordless — no credential.
- **App-tile launchpad** (`/` with an SSO session) — an Okta-style grid of one
  tile per registered client (from the tile metadata); clicking a tile navigates
  to its `launch_url`. **Log out** clears the session; **switch user** logs out
  and returns to the picker.

The frontend lives in `ui/` and is built on the **devedge-ufe-sdk** core: it
adapts the IdP SSO session to the `@infobloxopen/devedge-ufe-core`
`SessionProvider` seam (`ui/src/session.ts`) and drives logout / switch /
tile-launch through that contract over the window-pinned auth-event bus. The
pages are also server-rendered, so the flow works with no JavaScript and is
assertable headlessly.

Build the frontend (only needed after editing `ui/src`; the bundle is committed
to `internal/idp/assets/`):

```sh
npm --prefix ui install
npm --prefix ui run build   # esbuild → internal/idp/assets/launchpad.js
```

## Dev authz service

`cmd/devauthz` is the decisions half of the suite: the out-of-process,
hot-reloadable sibling of the SDK's in-process `authz.DevAuthorizer`. It runs on
the same devedge-sdk server harness and serves the dev authz wire protocol so a
microservice's `authz.Authorizer` can be a live, editable service instead of a
compiled-in rule set.

> **NON-PRODUCTION.** The admin endpoint is **unauthenticated** and grants are
> in-memory / file-backed. Production authorization is OPA/PARGS behind the
> **same** `authz.Authorizer` seam: a service swaps `Authorizer:
> &devsvc.Client{...}` for `Authorizer: opaauthz.New(...)` with no other code
> change.

### Run it

```sh
go run ./cmd/devauthz
# or with explicit addresses / a grants file:
DEVAUTHZ_HTTP_ADDR=:8090 DEVAUTHZ_GRPC_ADDR=:9091 DEVAUTHZ_GRANTS=./grants.json go run ./cmd/devauthz
```

Flags mirror the env vars: `-http-addr` (default `:8090`), `-grpc-addr` (default
`:9091`; the harness requires one even though this service is HTTP-only), and
`-grants` (default `./grants.json`). When the grants file is absent the service
starts **empty = default-deny** — the admin `PUT` still works.

### Endpoints served (on the HTTP port)

| Path | Method | Purpose |
|------|--------|---------|
| `/v1/authorize` | `POST` | decide one request (body: principal + verb + resource); returns `{"allow":bool,"reason":...}` |
| `/v1/grants` | `PUT` | replace the whole grant set live (body: JSON array of grants) |
| `/healthz`, `/readyz` | `GET` | SDK liveness / readiness probes (always win over `/v1/`) |

### Grants file

`grants.json` is a JSON array of grants (see the shipped sample). Each grant is
`{Tenant, Subjects, Verbs, Resource}`; `*` is a wildcard, and group membership is
matched as `group:<name>`:

```json
[
  {"Tenant": "*", "Subjects": ["group:admin"],  "Verbs": ["*"],          "Resource": "*"},
  {"Tenant": "*", "Subjects": ["group:viewer"], "Verbs": ["get","list"], "Resource": "order"}
]
```

### Flip a grant live (no restart)

Two ways, both hot:

**Edit the file** — the service polls its mtime every second and reloads
(keeping the last-good set on a bad edit):

```sh
# grant group:viewer delete on order, then save — the next decision reflects it
$EDITOR grants.json
```

**Or `PUT` a new set over the wire:**

```sh
curl -X PUT http://127.0.0.1:8090/v1/grants \
  -H 'Content-Type: application/json' \
  -d '[{"Tenant":"*","Subjects":["group:ops"],"Verbs":["delete"],"Resource":"order"}]'

# ask a decision:
curl -X POST http://127.0.0.1:8090/v1/authorize \
  -H 'Content-Type: application/json' \
  -d '{"principal":{"Subject":"opsuser","Groups":["ops"]},"verb":"delete","resource":{"Type":"order"}}'
# -> {"allow":true,"reason":"dev grant matched"}
```

## Acceptance tests

- `cmd/idp/acceptance_test.go` boots the IdP through the real
  `server.New(...).Serve` path and, with no browser, drives a full
  confidential-client **auth-code + PKCE** round-trip, then verifies the returned
  `id_token` against the served JWKS and asserts the coarse-claims rule.
- `cmd/idp/launchpad_test.go` proves the **clients-file hot-reload** (boot with a
  clients file → its client/tile is registered; edit to add a second → it appears
  with no restart; a bad edit keeps last-good) and the **picker → launchpad →
  logout** flow at the HTTP level (served content + SSO session cookie).
- `e2e/twotier_test.go` proves the two-tier trust chain (IdP identity → app
  identity mints the bearer → microservice verifies the app's JWKS).
- `e2e/verifydecide_test.go` proves the full **VERIFY→DECIDE** pipeline against a
  live dev authz service: a verified bearer is **denied** (empty grants), then
  the SAME call is **allowed** after a live grant flip, and a garbage bearer is
  rejected at verify before authz is consulted.

```sh
go build ./... && go test ./...
```
