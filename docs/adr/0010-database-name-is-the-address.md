# The database name is the address

A client picks the environment in the database name: `<env>/<db>` or `<env>/<instance>/<db>`. The connector strips the environment and forwards `<instance>/<db>`, resolving a bare `<db>` through the environment's discovery and refusing an ambiguous one. There is no default environment, so a bare name fails and lists the environments: whoever reads a connection string, a log line or an agent's query sees which deployment it touches, and nothing reaches prod by accident.
