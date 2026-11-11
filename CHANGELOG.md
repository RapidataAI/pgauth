# Changelog

## v0.3.1

- `pgauth connect` redirects to a fixed `http://127.0.0.1:8250/callback` for issuers that need an exact redirect URI. `--callback-port` / `callbackPort` changes it; 0 restores the random port.

## v0.3.0

pgauth now decides access itself from Kubernetes-style role bindings ([ADR 0007](docs/adr/0007-pgauth-decides-from-role-bindings.md)).

**Breaking**
- The `postgres:roles` claim is no longer read. Remove `oidc.rolesClaim` and `groups` from the config; strict parsing rejects both.
- `rbac.dir` is required: access comes from `PgRole` / `PgRoleBinding` YAML (`apiVersion: pgauth.dev/v1alpha1`) in it. With no binding nobody connects.
- A token needs the `postgres:read` or `postgres:write` scope (`oidc.scopes`); read caps the level at read.
- `/readyz` stays 503 until a valid set of access rules has loaded.

**Added**
- `oidc.usernameClaim` (default `email`), `oidc.groupsClaim` (default `groups`), `oidc.groupsPrefix`.
- Built-in roles `pg-admin`, `pg-reader` and `<instance>.<db>.read|write`.
- Reload on change with last-valid-wins, metrics `pgauth.rbac.loads` and `pgauth.rbac.rejected`, and rejection details on `/readyz`.
- `pgauth lint [--config <file>] <dir>` for CI; it warns about `User` names with uppercase letters.
- `groupRoles` (defaults `{db}_read` / `{db}_write`) names the Postgres group role per level; write joins both.
- The connect span and log carry `user`, `groups`, `bindings`, `level` and `scope_cap` instead of `roles`.

## v0.2.0

- `pgauth connect`: browser login with PKCE, refresh token in the OS keychain, localhost forwarding. Release binaries for macOS and Linux.

## v0.1.0

- `pgauth serve`: TLS Postgres proxy with temporary roles, gate check at connect, sweep, multi-replica safe role lifecycle.
