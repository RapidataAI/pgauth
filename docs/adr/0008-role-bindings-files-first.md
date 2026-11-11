# Role bindings are files first, CRDs later, with one format

pgauth reads `PgRole` / `PgRoleBinding` YAML from a directory and will later watch the same YAML as CRDs, so moving costs no rewrite. Validation is `pgauth lint` in CI plus last-valid-wins at runtime, not an admission webhook: a bad push cannot lock everyone out, and no webhook has to stay up.
