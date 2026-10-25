# Acceptance and release evidence

The principal acceptance test is `tests/test_integration.py::test_eight_step_cross_protocol_identity_lifecycle`. It uses the application and a real database, not mocked protocol handlers. The repeatable installed-environment check is `scripts/verify_live.py`.

## Run the checks

```sh
python -m pytest tests -q
```

Tests use a new temporary SQLite database unless `TEST_DATABASE_URL` points to a disposable PostgreSQL or MySQL database. The suite changes and deletes records. Never point it at an environment whose data must be retained.

After installing the application:

```powershell
.\scripts\lab.ps1 verify
```

```sh
sh scripts/lab.sh verify
```

## End-to-end workflow

| Step | Evidence |
|---|---|
| Enable adapters | Independent protocol switches remain enabled without disabling administration |
| Register client | Selected authentication methods, protocols, scopes and attribute policy persist; the secret appears once |
| Obtain credential | Client Credentials validates the client and restricts requested scopes |
| Provision identity | SCIM creates a canonical employee record |
| Assign and calculate access | REST role assignment and GraphQL effective permissions read the same identity |
| Verify employee portal | Banking modules and actions differ according to effective permissions |
| Disable identity | SOAP changes the account and REST, SCIM, GraphQL and the portal immediately reflect the state |
| Inspect evidence | Request metadata links transport, authentication, duration, user change and audit records |
| Revoke credential | Revoked token or client credentials fail on the next request |

## Adapter regression coverage

- REST, SCIM 2.0, SCIM 1.1, SOAP 1.1/1.2, GraphQL, OData, gRPC, JSON-RPC and CSV share canonical identity state.
- Native gRPC validates bearer metadata and returns canonical users.
- Webhook tests send a signed delivery to an actual local HTTP receiver and verify the signature and body.
- SFTP tests cover connector validation, private-address policy, pinned host-key requirements, encrypted password storage and safe-path enforcement. A public SFTP interoperability matrix remains deployment-specific because servers differ in algorithms and policy.
- Authentication regressions cover Client Credentials, PKCE, API key, Basic, Digest, JWT, HMAC replay protection, browser sessions and CSRF.
- Authorization regressions cover scope limits, bearer precedence, operation permission, attribute policy and maker/checker separation.
- Parser and resource controls cover XML entities, GraphQL depth/field limits, body size, bounded batches and CSV row limits.
- Host, OIDC, webhook and SFTP validation covers unsafe destinations and secret exposure.

## Release evidence: 25 October 2026

- Final Python 3.12 release image: **27 tests passed** against fresh temporary SQLite databases.
- Installed PostgreSQL workflow: **passed** on version 1.5.0, including SCIM 1.1, OData, JSON-RPC and CSV calls, attribute restrictions, OIDC mapping, permission-specific portal profiles, payment approval, transaction posting and session termination.
- Frontend production build: **passed**, approximately 357 KB JavaScript and 56 KB CSS before transport compression.
- Python dependency audit: **no known vulnerabilities found** in the resolved release environment.
- Production frontend dependency audit: **0 known vulnerabilities**.
- Browser review: sign-in, Command Center, Protocol Management, Authentication Studio, Request Explorer and Banking Portal rendered in the deployed PostgreSQL environment.
- Container health: HTTP application healthy on `127.0.0.1:8787`; native gRPC exposed on `127.0.0.1:50051`.

These results support the implemented profiles described in [CAPABILITIES.md](CAPABILITIES.md). They do not certify every optional feature of each standard and do not replace an independent penetration test, accessibility audit, load test or external conformance suite.
