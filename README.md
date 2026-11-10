# pgauth

pgauth lets people and programs log in to Postgres with a short-lived OIDC access token instead of a
database password. A client connects to pgauth with the token as its password; pgauth verifies the
token, creates a temporary Postgres role that holds exactly the rights the token lists, logs in
upstream as that role and passes bytes through. When the last connection using the role closes,
pgauth drops it.

```
psql "host=pgauth.example.com dbname=main/orders sslmode=verify-full" # password: an access token
```

## What pgauth is not

- **Not an authorization engine.** pgauth does not decide who may access what; it enforces what the
  token says. The decision belongs to whoever issues the token (your identity provider, which may in
  turn ask OpenFGA, SpiceDB or anything else). Projects like
  [pgauthz](https://github.com/thomasdarimont/pgauthz) evaluate authorization inside Postgres;
  pgauth does not.
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
4. The roles claim (for example `postgres:roles`) lists `<instance>/<db>:<relation>`. Each relation
   that matches the requested database maps to a group role through `groups` (default `reader` →
   `<db>_read`, `writer` → `<db>_write`). No match means no connection.
5. pgauth creates or reuses the temporary role `pgauth_<sub8>_<hash6>`, where `hash6` covers the
   subject, client and matched roles. The role is a member of the mapped groups and of `pgauth_temp`,
   carries `COMMENT ON ROLE` with the full subject, client and creation time, and has a password only
   pgauth knows. It never gets `VALID UNTIL` ([ADR 0003](docs/adr/0003-drop-roles-not-valid-until.md)).
6. pgauth logs in upstream as the role and splices the two connections. Access is checked only here,
   at connect ([ADR 0004](docs/adr/0004-check-at-the-gate-only.md)); `maxConnectionAge` (default 12h)
   bounds how long a connection lives.
7. When the last connection using a role closes, pgauth drops the role.

Cancel requests work: pgauth hands the client its own cancel key and forwards cancels upstream.

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
  issuer's keys are loaded and every instance accepts the issuer login (and its startup sweep ran).
- **Audit:** every connection attempt writes one JSON log line and one OpenTelemetry span
  `pgauth.connect` with `sub`, `client_id`, `instance`, `db`, `roles`, `decision`, `reason`, `role`
  and duration. Query text is never recorded. Spans are exported when the standard
  `OTEL_EXPORTER_OTLP_*` variables are set.

### Multiple replicas

Several pgauth pods can serve one instance. Each create, reuse and drop of a role runs under a
Postgres advisory lock on the role name, and every pod derives the same password for a role from
the shared issuer credential. A pod drops a role on its last local close only when `pg_stat_activity`
shows no session of that role (another pod's); the startup sweep drops only `pgauth_temp` members
with no session that were created more than `sweepMinAge` (5 minutes) ago. A role whose last session
closed on a pod that then crashed stays until some pod restarts and sweeps it.

## Connecting as a person

`pgauth connect` is the connector: it logs you in through the browser (authorization code + PKCE
against a public OIDC client whose redirect URIs allow `http://127.0.0.1/*`), keeps the refresh token
in the OS keychain (macOS Keychain, Secret Service on Linux), and listens on `127.0.0.1:5432`. Every
connection a local client opens is forwarded to pgauth over TLS with a fresh token as the password.

```
pgauth connect --issuer https://auth.example.com --client-id pgauth-cli \
  --resource https://postgres.example.com --scope "openid offline_access postgres:read" \
  --server pgauth.example.com:5432 [--server-ca internal-ca.pem] [--listen 127.0.0.1:5432]
psql "host=127.0.0.1 dbname=main/orders"
```

The flags can live in `connect.yaml` under your user config directory (`~/Library/Application
Support/pgauth/` on macOS, `~/.config/pgauth/` on Linux) as `issuer`, `clientId`, `resource`, `scope`,
`server`, `serverCA` and `listen`; see [`connect.example.yaml`](connect.example.yaml) and, for one
real deployment, [`examples/rapidata-test/connect.yaml`](examples/rapidata-test/connect.yaml). Any process of yours that can reach the local port connects with
your rights, the same trade-off as other local database proxies.

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
