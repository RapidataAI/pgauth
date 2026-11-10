# Temporary roles are dropped, never expired with VALID UNTIL

`VALID UNTIL` only blocks new logins and leaves open sessions running (measured on PG 18.6), so pgauth removes access by dropping the role: when the holder's last connection closes, or when a crashed pgauth's leftovers are swept. Temporary roles get rights only through group roles, which keeps `DROP ROLE` possible without per-database cleanup.
