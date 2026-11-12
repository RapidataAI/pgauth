# The database name is the address

A client picks the environment in the database name: `<env>/<db>` or `<env>/<instance>/<db>`. The connector strips the environment and forwards `<instance>/<db>`, resolving a bare `<db>` through the environment's discovery and refusing an ambiguous one. There is no default environment, so a bare name fails and lists the environments: whoever reads a connection string, a log line or an agent's query sees which deployment it touches, and nothing reaches prod by accident.

The one exception is opt-in: a listener bound to an environment (`listeners: [{listen, env}]`, added by `pgauth env add --ide-port`) resolves bare `<db>` and `<instance>/<db>` inside that environment and refuses names of any other environment. IDEs such as DataGrip and Rider browse `pg_database` and connect by bare name, which the main port must refuse. The environment is still explicit, in the port the data source points at, and vessel configs never set listeners.
