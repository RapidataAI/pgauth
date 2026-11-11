# pgauth decides access from role bindings; the token only proves identity

Supersedes 0002 and amends 0005 and 0006. pgauth now decides read, write or nothing per database from `PgRole` / `PgRoleBinding` YAML shaped like Kubernetes RBAC, matched against the token's user and groups and capped by its scope; the identity service no longer lists grants in a `postgres:roles` claim. Access then lives in reviewed files next to the deployment instead of a second store, and pgauth stays IdP-agnostic because only claim names are configured.
