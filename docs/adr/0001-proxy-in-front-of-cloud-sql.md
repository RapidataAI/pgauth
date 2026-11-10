# Tokens are checked by pgauth, not by Postgres

Postgres 18 can verify OAuth tokens through a validator module, but Cloud SQL doesn't allow loading one (`oauth_validator_libraries` isn't a supported flag). So a proxy, pgauth, verifies the database token and connects to Cloud SQL itself. Cloud SQL IAM auth was rejected because access would then live in Google groups instead of OpenFGA.
