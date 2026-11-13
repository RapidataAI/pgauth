# pgauth

Public, provider-agnostic Postgres proxy: OIDC access token as password → temporary role → spliced connection. Read `GLOSSARY.md` for the terms and `docs/adr/` before changing behaviour.

- `cmd/pgauth` CLI · `internal/proxy` wire protocol, gate check, splice · `internal/connect` connector (browser login, keychain, localhost forward) · `internal/rbac` PgRole/PgRoleBinding parsing, lint and reload · `internal/roles` temporary-role lifecycle · `internal/telemetry` OTel traces/metrics/logs and the stdout+OTLP logger · `internal/token` JWT verification · `internal/config` YAML.
- Nothing Rapidata- or OpenFGA-specific in code (ADR 0005): issuer, audience, claim names, scopes, group roles and allowlists are config; access comes from RBAC YAML (ADR 0007).
- `go test ./...` needs Docker (testcontainers, `postgres:18`). Keep tests table-driven against the real database; no mocks of Postgres.
- `gofmt`, `go vet` and the tests gate CI. Releases are tags `vX.Y.Z`; tags are never moved.
- Never log or trace query text or tokens. Never rely on `VALID UNTIL` to end access; dropping the role does (ADR 0003, 0012).
