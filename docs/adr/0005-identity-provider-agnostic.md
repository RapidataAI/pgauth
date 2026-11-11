# pgauth knows nothing about Rapidata or OpenFGA

Status: amended by [0007](0007-pgauth-decides-from-role-bindings.md): access is decided in pgauth from role bindings.

pgauth is meant to be open-sourced, so it trusts any OIDC issuer: issuer, audience, the claim that lists roles, and an allowlist are configuration. Deciding who gets which roles (our OpenFGA, the identity service, the agent ceiling) stays in Rapidata's own services, the same split ClickHouse Cloud makes with its configurable roles claim.
