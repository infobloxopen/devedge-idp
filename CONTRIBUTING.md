# Contributing to devedge-idp

## Conventions

### Config key naming: snake_case for the dev config files

The dev-manipulable config files this app reads — `idp-clients.yaml` (the client/tile registry
`de idp clients sync` writes) and `grants.yaml` (the `cmd/devauthz` grants) — use **snake_case**
keys:

- `idp-clients.yaml`: `client_id`, `client_secret`, `redirect_uris`, and a `tile` with
  `name`/`description`/`icon_url`/`launch_url`.
- `grants.yaml`: `tenant`, `subjects`, `verbs`, `resource`.

This matches the Go `json` struct tags and the OAuth2/OIDC spec (`client_id`, `redirect_uris` are
snake_case by definition). Keep new keys snake_case, and give any struct that also serializes to a
Kubernetes-style manifest both tags (`json:"..." yaml:"..."`).

> Note the intentional split: a launchpad **tile** is snake_case here (`name`/`launch_url`) but
> camelCase in a `devedge.yaml` route (`displayName`/`launchURL`), because that file is a
> Kubernetes-style manifest. `de idp clients sync` maps between them; don't unify them.

The canonical statement of the devedge naming rule ("camelCase for manifests, snake_case
elsewhere") is in the devedge-sdk style guide:
<https://github.com/infobloxopen/devedge-sdk/blob/main/docs/STYLE-GUIDE.md> ("Configuration key
naming").
