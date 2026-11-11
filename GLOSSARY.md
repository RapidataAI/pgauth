# pgauth

Scoped access to Rapidata's Postgres databases: who may read or write which database, decided and enforced by pgauth from role bindings.

## Language

**Database grant**:
The right to read or write one Postgres database or a whole instance, written as a grant of a `PgRole`. Any account can be bound to one, not only staff.
_Avoid_: permission, access right, ACL

**Role binding**:
A `PgRoleBinding` that gives one `PgRole`'s database grants to users and groups named in the token.
_Avoid_: assignment, membership

**Database scope**:
The OAuth scope `postgres:read` or `postgres:write` a token was issued with; pgauth caps the access from role bindings by it. Vessels hold `postgres:read`; `postgres:write` is only issued inside an approved write run.
_Avoid_: agent ceiling, agent limit

**Database token**:
A short-lived token for the Postgres audience that proves who the holder is (user and groups) and carries a database scope; it lists no grants.
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
