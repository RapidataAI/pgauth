# pgauth

Scoped access to Rapidata's Postgres databases: who may read or write which database, decided in OpenFGA and enforced by pgauth.

## Language

**Database grant**:
The right of one identity-service account to read (`reader`) or write (`writer`) one Postgres database or a whole instance, set by a platform admin. Any account can hold one, not only staff.
_Avoid_: permission, access right, ACL

**Database scope**:
The OAuth scope `postgres:read` or `postgres:write` a token was issued with; it caps the database grants a token may carry. Vessels hold `postgres:read`; `postgres:write` is only issued inside an approved write run.
_Avoid_: agent ceiling, agent limit

**Database token**:
A short-lived token whose `postgres:roles` claim lists `<instance>/<db>:reader|writer`: the holder's database grants, capped by its database scope.
_Avoid_: JWT, access token, credential

**pgauth**:
The proxy that accepts a database token as a Postgres password and connects on the holder's behalf.
_Avoid_: pg-gate, proxy, gateway

**Temporary role**:
A Postgres login pgauth creates for one holder and set of rights, and drops when the holder's last connection closes.
_Avoid_: temp user, ephemeral user, dynamic credential

**Group role**:
A Postgres role, one per database and level, that carries the actual table privileges a temporary role joins.
_Avoid_: db role, permission role

**Gate check**:
The one moment access is decided: when a connection opens. An open connection is not re-checked.
_Avoid_: session check, re-validation

**Connector**:
The local program a person runs (`pgauth connect`) that logs them in through the browser and lets any Postgres client reach pgauth through `localhost`.
_Avoid_: helper, CLI, local proxy

**Instance**:
One Postgres server pgauth can reach, such as the main Cloud SQL or the bidder cluster's Postgres. Database names are only unique within an instance.
_Avoid_: server, cluster, host
