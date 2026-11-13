# pgauth

pgauth lets people and programs log in to Postgres with a short-lived OIDC access token instead of a
database password. A client connects to pgauth with the token as its password; pgauth verifies the
token, looks up what the holder may do in Kubernetes-style role bindings, creates a temporary Postgres
role with exactly that access, logs in upstream as that role and passes bytes through. When the last connection using the role closes,
pgauth drops it.

```
psql "host=pgauth.example.com dbname=main/orders sslmode=verify-full" # password: an access token
```

## What pgauth is not

- **Not a fine-grained authorization engine.** pgauth decides one thing: read, write or nothing on a
  whole database, from role bindings (see [Access model](#access-model)). Table, row and column rules
  stay in Postgres grants. Projects like [pgauthz](https://github.com/thomasdarimont/pgauthz) evaluate
  authorization inside Postgres; pgauth does not.
- **Not a connection pooler.** Every client connection is one upstream connection. PgBouncer or
  another pooler can sit behind pgauth if you need pooling.
- **Not a query firewall.** pgauth never reads query text. Rights come only from the Postgres group
  roles the temporary role joins.

## How it works

1. The client sends `SSLRequest`; pgauth requires TLS before anything else.
2. The startup message's database is `<instance>/<db>`. pgauth asks for a cleartext password, which
   is the access token.
3. pgauth verifies the token against the issuer's JWKS: signature, `iss`, `aud`, `exp`, and the client
   allowlist.
4. The token names a user (`email` by default) and groups (`groups`). The role bindings decide the
   level on the requested database, the token's scope caps it (see [Access model](#access-model)),
   and the level picks the group roles: read joins `<db>_read`, write joins `<db>_read` and
   `<db>_write` (`groupRoles`). No access means no connection.
5. pgauth creates or reuses the temporary role `pgauth_<sub8>_<hash6>`, where `hash6` covers the
   subject, client, database and level. The role is a member of those group roles and of
   `pgauth_temp`, carries `COMMENT ON ROLE` with the full subject, user, client and creation time, and
   has a password only pgauth knows. It never gets `VALID UNTIL` ([ADR 0003](docs/adr/0003-drop-roles-not-valid-until.md)).
6. pgauth logs in upstream as the role and splices the two connections. Access is checked only here,
   at connect ([ADR 0004](docs/adr/0004-check-at-the-gate-only.md)); `maxConnectionAge` (default 12h)
   bounds how long a connection lives.
7. When the last connection using a role closes, pgauth drops the role.

Cancel requests work: pgauth hands the client its own cancel key and forwards cancels upstream.

## Access model

pgauth reads `PgRole` and `PgRoleBinding` resources from every `*.yaml` file in `rbac.dir` (several
documents per file are fine; `kustomization.yaml` is skipped). They work like Kubernetes RBAC:

```yaml
apiVersion: pgauth.dev/v1alpha1
kind: PgRole
metadata: {name: analytics-reader}
spec:
  grants:
    - {instance: cloudsql-main, database: order, level: read}  # level: read|write; database "*" = every database of the instance
---
apiVersion: pgauth.dev/v1alpha1
kind: PgRoleBinding
metadata: {name: mari-order}
spec:
  roleRef: {kind: PgRole, name: cloudsql-main.order.read}
  subjects:
    - {kind: Group, name: postgres-admins}
    - {kind: User, name: mari@example.com}
```

- **Subjects.** `User` matches the token's `oidc.usernameClaim` (default `email`), ignoring case
  (Unicode simple case folding) unless `oidc.usernameCaseInsensitive: false`, because issuers often
  keep the stored casing of an email. `Group` matches each entry of `oidc.groupsClaim` (default
  `groups`) exactly, after `oidc.groupsPrefix` is prepended; the claim may be an array or, for a single
  group, a plain string.
- **Built-in roles** need no YAML: `pg-admin` (write on every configured database), `pg-reader`
  (read on every configured database), and `<instance>.<db>.read` / `<instance>.<db>.write` for
  every database in `instances`. A `PgRole` may not reuse their names.
- **Effective access** is the highest level over every binding that matches the user or one of their
  groups. Write implies read.
- **Scope cap.** After the bindings, the token's scope caps the level: `postgres:read` caps at read,
  `postgres:write` allows write, a token with neither is refused (`oidc.scopes` renames them). This is
  how a token issued to an agent stays read-only although its owner may write.
- **Reloading.** pgauth rereads the directory every `rbac.reloadInterval` (10s) and loads a change
  only after two identical reads 100 ms apart, so a file being written is picked up once it is
  complete. A set with any error is rejected as a whole and the last valid set stays live; a file with
  no `PgRole` or `PgRoleBinding` (for example one caught empty mid-write) counts as an error, so
  delete a file rather than emptying it; the rejection is logged, counted in the
  `pgauth.rbac.loads{result="rejected"}` metric, flagged by the `pgauth.rbac.rejected` gauge and shown
  in the `/readyz` body. pgauth becomes ready only once a first valid set has loaded.
- **Lint in CI.** `pgauth lint [--config config.yaml] <dir>` checks the schema, unknown fields,
  duplicate names, role references, subject kinds and, with `--config`, every instance, database and
  generated role against the config, and, when `oidc.usernameCaseInsensitive` is false, warns (exit 0) about `User` names with uppercase
  letters. It reads only those files (not the TLS or credentials files they
  name), makes no network calls, prints `file:line: message` and exits 1 on any error.

Files first, CRDs later with the same format, and lint plus last-valid-wins instead of an admission
webhook: [ADR 0008](docs/adr/0008-role-bindings-files-first.md).

Every connection attempt records the matched bindings, the level they grant, the level after the cap
and the cap itself
(see [Running](#running)).

## Preparing an instance

Run once per instance as a superuser (Cloud SQL: a `cloudsqlsuperuser` member), and once per database:

```sql
-- per instance
CREATE ROLE pgauth_temp NOLOGIN;
CREATE ROLE pgauth LOGIN PASSWORD '...' CREATEROLE;
GRANT pg_signal_backend TO pgauth;
GRANT pgauth_temp TO pgauth WITH ADMIN TRUE, INHERIT FALSE, SET FALSE;

-- per database <db>, whose tables are owned by <db>_service
CREATE ROLE <db>_read NOLOGIN;
CREATE ROLE <db>_write NOLOGIN;
GRANT <db>_read, <db>_write TO pgauth WITH ADMIN TRUE, INHERIT FALSE, SET FALSE;

-- per database <db>, connected to <db>
GRANT USAGE ON SCHEMA public TO <db>_read, <db>_write;
ALTER DEFAULT PRIVILEGES FOR ROLE <db>_service IN SCHEMA public
  GRANT SELECT ON TABLES TO <db>_read;
ALTER DEFAULT PRIVILEGES FOR ROLE <db>_service IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO <db>_write;
-- tables that already exist need the same grants once:
GRANT SELECT ON ALL TABLES IN SCHEMA public TO <db>_read;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO <db>_write;
```

pgauth needs only `ADMIN` on the groups. `INHERIT FALSE, SET FALSE` is the recommendation, so the issuer
login holds none of the groups' rights itself, but it is optional: some tools (for example Terraform /
OpenTofu Postgres providers) cannot express it, and plain `WITH ADMIN OPTION` works too. Temporary roles
get rights only through the groups, so `DROP ROLE` needs no per-database cleanup.

**Optional hardening.** pgauth only ever connects a temporary role to the database its token names, so
this is not needed for pgauth to be safe. If no other login relies on `PUBLIC` having `CONNECT`, you can
also keep temporary roles out of other databases at the Postgres level:

```sql
REVOKE CONNECT, TEMPORARY ON DATABASE <db> FROM PUBLIC;
GRANT CONNECT ON DATABASE <db> TO <db>_service, <db>_read, <db>_write; -- plus every other login that uses <db>
```

## Running

```
pgauth serve --config /etc/pgauth/config.yaml
```

See [`config.example.yaml`](config.example.yaml) for every setting. Upstream `sslmode` takes the libpq
values; `require` encrypts without verifying the server certificate, `verify-ca` / `verify-full` with
`sslrootcert` also verify it. The image
`ghcr.io/rapidataai/pgauth:vX.Y.Z` runs as non-root and needs no writable filesystem.

- **Health:** `GET /healthz` answers while the process runs; `GET /readyz` answers 200 once the
  issuer's keys and a valid set of access rules are loaded and every instance accepts the issuer login
  (and its startup sweep ran); its body reports a rejected rules change.
- **HTTPS API** (`http.listen`, same certificate as Postgres; [ADR 0011](docs/adr/0011-serve-publishes-discovery-and-access.md)):
  - `GET /.well-known/pgauth` → `{postgres, issuer, audience, cli_client_id, scopes: {read, write},
    instances: [{name, databases}]}`, public, so a connector can set itself up from a host name.
  - `GET /v1/access` with `Authorization: Bearer <token>` → `[{instance, database, level}]`: every
    database the token reaches, after the bindings and the scope cap.
- **Audit:** every connection attempt writes one JSON log line and one OpenTelemetry span
  `pgauth.connect` with `sub`, `user`, `groups`, `client_id`, `instance`, `db`, `bindings`, `granted`
  (level from the bindings), `level` (after the cap), `scope_cap`, `decision`, `reason`, `role` and duration. Query text is never recorded.
- **Telemetry:** when the standard `OTEL_EXPORTER_OTLP_*` variables are set, spans, metrics and logs
  go out over OTLP with `service.name=pgauth`; `OTEL_LOGS_EXPORTER=none` (or `_TRACES_` / `_METRICS_`)
  switches one signal off. Every log line still goes to stdout as JSON as well, and the connect record
  carries the trace and span ids of its `pgauth.connect` span.

### Multiple replicas

Several pgauth pods can serve one instance. Each create, reuse and drop of a role runs under a
Postgres advisory lock on the role name, and every pod derives the same password for a role from
the shared issuer credential. A pod drops a role on its last local close only when `pg_stat_activity`
shows no session of that role (another pod's); the startup sweep drops only `pgauth_temp` members
with no session that were created more than `sweepMinAge` (5 minutes) ago. A role whose last session
closed on a pod that then crashed stays until some pod restarts and sweeps it.

## Connecting as a person

`pgauth connect` is the connector. It listens on `127.0.0.1:5432` and forwards every client
connection to the right pgauth over TLS, with a fresh token as the password. The database name is
the address ([ADR 0010](docs/adr/0010-database-name-is-the-address.md)):

```
psql "host=127.0.0.1 dbname=prod/order"                # <env>/<db>, the instance is looked up
psql "host=127.0.0.1 dbname=prod/cloudsql-main/order"  # <env>/<instance>/<db>
```

There is no default environment: a bare `order` fails with `use <env>/<db>; environments: prod,
test`, and a name on several instances fails and lists the full addresses. `<env>/<db>` is looked up
in the server's discovery (3 s timeout); the last answer is kept in the user cache directory (or next
to the config), so a short API outage does not break it. With no answer at all the connection fails
with `pgauth api https://<host>:8443 unreachable (<cause>); use <env>/<instance>/<db> to connect
without it`, and `<env>/<instance>/<db>` never needs the API.

1. `pgauth env add prod pgauth.example.com` reads the server's discovery
   (`https://<host>:8443/.well-known/pgauth`), pins its issuer and CLI client in `connect.yaml`, logs
   you in through the browser and lists what you can reach. `--write` asks for the write scope,
   `--ca file` trusts a private CA, `--ide-port` adds an IDE port (below), `--no-login` skips the login. Adding an environment again with a
   different issuer is refused without `--force`.
2. `pgauth connect`, or `pgauth service install` to run it at login (launchd on macOS, a systemd user
   unit on Linux; `service uninstall` removes it).
3. `pgauth ls [env]` lists every database you can reach and your level, from the server's
   `/v1/access`.

`pgauth env list`, `env login <name>` (log in again) and `env remove <name>` (also deletes the
keychain entry) manage environments. `connect.yaml` is `--config`, else `$PGAUTH_CONFIG`, else
`<user config dir>/pgauth/connect.yaml`; see [`connect.example.yaml`](connect.example.yaml) and
[`examples/rapidata-test/connect.yaml`](examples/rapidata-test/connect.yaml).

**Tokens** come from a browser login (authorization code + PKCE; redirect
`http://127.0.0.1:8250/callback`, `callbackPort: 0` for any free port; refresh token in the OS keychain,
one per environment) or from a file that something else keeps fresh (`token: {file, field,
statusFile}`, re-read on every connection). The connector never runs a command
([ADR 0009](docs/adr/0009-tokens-from-login-or-file.md)). A missing, unreadable or expired token file
fails only that connection, with `FATAL 28000` carrying the status file's text (or the path); the next
connection reads the file again. A database without a binding fails with serve's own text, passed through unchanged:
`no access to cloudsql-main/payment for luca@example.com: no binding grants it. <accessHelp>`, where
the server's `accessHelp` says where to ask for access. `pgauth ls` shows the same help when nothing is
reachable.

Any process of yours that can reach the local port connects with your rights, the same trade-off as
other local database proxies.

The v0.4 format (top-level `server`/`issuer`, `listeners` per instance) still loads in v0.5 with a
deprecation warning and stops loading in v0.6.

### IDEs (DataGrip/Rider)

IDEs browse every database in `pg_database` and connect by bare name, which the main port refuses. Give
each environment its own port instead: `pgauth env add prod <host> --ide-port 15432` (or by hand,
`listeners: [{listen: 127.0.0.1:15432, env: prod}]`). On that port `order` and `<instance>/order`
resolve inside prod, and a name of another environment (`test/order`) is refused.

Create one data source per environment on its port, with any user, no password and SSL off. Databases
pgauth does not serve fail with `serves no database`; limit the data source's **Schemas** tab to the
databases you use to keep the IDE quiet.

Binaries for macOS (arm64, amd64) and Linux (amd64, arm64) are attached to each
[GitHub release](https://github.com/RapidataAI/pgauth/releases). A binary downloaded with a browser
on macOS is quarantined; download it with `curl` or run `xattr -d com.apple.quarantine pgauth`.

## Development

```
go test ./...   # needs Docker: the tests run against postgres:18 through testcontainers
```

Design decisions are in [`docs/adr`](docs/adr) and the vocabulary in [`GLOSSARY.md`](GLOSSARY.md).

## License

Apache-2.0
