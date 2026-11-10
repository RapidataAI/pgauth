# The identity service decides; pgauth only reads the token

The identity service checks OpenFGA when it issues a database token and writes the result into `postgres:roles`; pgauth never calls OpenFGA. This keeps one decider, the same split ClickHouse Cloud makes with `clickhouse:roles`. The cost is that a revoke only stops new connections (see 0004).
