# Agents are capped by OAuth scope, not by an OpenFGA agent ceiling

Status: amended by [0007](0007-pgauth-decides-from-role-bindings.md): the scope still caps agents, applied by pgauth after the role bindings; there is no OpenFGA model.

Postgres follows the Rapidata API model: a vessel's token is its owner's grant narrowed to `postgres:read` by the gateway's existing exchange, and `postgres:write` is only issued inside an approved write run. The OpenFGA model therefore has only `reader`/`writer`, unlike ClickHouse's per-database agent ceiling, so a vessel can read everything its owner can read.
