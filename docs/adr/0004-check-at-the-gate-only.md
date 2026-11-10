# Access is checked when a connection opens, not during it

pgauth checks the database token only at connect, the way ClickHouse checks its JWT users at login; an open connection keeps running after its token expires. Re-checking would need pgauth to call the identity service for every open session. The cost: a revoke stops new connections at once, but an open session lives until it disconnects.
