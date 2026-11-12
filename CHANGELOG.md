# Changelog

## v0.4.1

- A rules file with no `PgRole` or `PgRoleBinding` (empty or only comments) is invalid, in `pgauth lint` and at runtime: a file read empty mid-write no longer replaces the live set with zero bindings. Delete a file instead of emptying it.
- Reloads wait for two identical reads 100 ms apart before loading a change, so a file edited in place is not loaded half-written.

## v0.4.0

- `pgauth connect` takes `listeners`, one local port per instance: a bare database name on an instance listener becomes `<instance>/<db>`, so IDEs such as DataGrip and Rider can browse an instance as one data source. All listeners share one login. The top-level `listen` keeps working unchanged; `--instance` gives `--listen` an instance. Each connection logs its database, e.g. `order → cloudsql-main/order`. `pgauth serve` is unchanged.

## v0.3.2

- The connect log line and span carry `granted` (the level from the bindings, before the scope cap) next to `level` (effective), so the audit shows when a scope reduced write to read.

## v0.3.1

- `User` subjects match the username claim ignoring case (`oidc.usernameCaseInsensitive`, default true), since issuers keep an email's stored casing. `pgauth lint` warns about uppercase `User` names only when the option is false.
- The groups claim may be a single string as well as an array; a string is one group.
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
