# Temporary roles are dropped, never expired with VALID UNTIL

Status: amended by [0012](0012-each-process-owns-its-roles.md): VALID UNTIL is set as an extra cap on new logins with a self-set password; dropping still ends access.

`VALID UNTIL` only blocks new logins and leaves open sessions running (measured on PG 18.6), so pgauth removes access by dropping the role: when the holder's last connection closes, or when a crashed pgauth's leftovers are swept. Temporary roles get rights only through group roles, which keeps `DROP ROLE` possible without per-database cleanup.
