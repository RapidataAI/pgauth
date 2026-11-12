# pgauth serve publishes discovery and access over HTTPS

pgauth serve answers `GET /.well-known/pgauth` (Postgres address, issuer, audience, CLI client, scopes, instances and databases) and `GET /v1/access` (what a bearer token reaches after bindings and the scope cap) on an HTTPS port with the Postgres certificate. A connector then needs only a host name to set itself up and to list what someone may use, and the answer comes from the same rules that gate connections, so it cannot drift.
