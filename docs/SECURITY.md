# Security model and standards review

This is a local synthetic integration lab, not a production identity provider or certified standards implementation. Bind it to loopback by default. Use generated installation credentials and do not publish disposable demo credentials.

## Authoritative references

- [SCIM protocol RFC 7644](https://www.rfc-editor.org/rfc/rfc7644): resource operations, PATCH, filtering, errors and capability discovery.
- [SCIM schemas RFC 7643](https://www.rfc-editor.org/rfc/rfc7643): core User and Group attributes and extension structure.
- [OAuth security RFC 9700](https://www.rfc-editor.org/rfc/rfc9700): token and authorization-flow security guidance.
- [OWASP API Security Top 10, 2023](https://owasp.org/API-Security/editions/2023/en/0x11-t10/): API threat-model baseline.

The tests verify a documented subset. They do not establish full RFC conformance or an independent security audit.

## Authentication boundaries

The implemented OAuth grant is confidential-client Client Credentials, authenticated with a client secret. Granted scopes are constrained by the client's registered scopes. Access tokens are opaque server-side records with expiry and revocation checks. Client secret rotation revokes existing client tokens. Unsupported grants must be rejected rather than silently mapped to Client Credentials.

PKCE belongs to interactive authorization-code flows and is not applied to Client Credentials. API Authorization Code and upstream OIDC federation require S256 PKCE, state, nonce and exact redirect checks. OIDC ID tokens require RS256/JWKS signature, issuer, audience and expiry validation. Refresh-token rotation, mTLS and device flow remain future work. Never add implicit or password grants as convenient substitutes.

Portal login is an application username/password session, not an OAuth password grant. Portal cookies are HttpOnly; cookie-authenticated mutations require the CSRF token returned at login. When an explicit bearer credential is supplied, failure must reject the request rather than fall back to an unrelated privileged browser cookie.

## Threat model and verification

| Risk | Implemented control / regression boundary | Remaining limitation |
|---|---|---|
| Broken object authorization | Server permission checks on identity operations; payment maker/checker | No multi-tenant authorization model or row-level branch policy |
| Broken authentication | Password and secret hashes, token expiry/revocation, disabled-user rejection | No MFA, WebAuthn or external identity provider |
| Property-level authorization | Explicit resource fields; password hashes omitted | Each new mutation field must receive a permission review |
| Function-level authorization | OAuth scopes, portal permissions, separate administration routes | Review all newly added routes before exposing them |
| Resource exhaustion | 1 MiB mutation payload cap; GraphQL document length, nesting depth and expanded-field caps; login/token rate limits | In-process limits are not distributed DDoS protection; no production load guarantee |
| Sensitive business flows | Synthetic payments and separate maker/checker | No real funds or financial compliance claim |
| SSRF | OIDC destinations require absolute HTTPS URLs, reject credentials and private/reserved/loopback targets, and re-check resolved addresses before outbound requests | DNS rebinding resistance needs an egress proxy or firewall for high-risk public hosting |
| Misconfiguration | Loopback binding, trusted Host allow-list, secure-header policy, optional HSTS and explicit capability status | TLS termination, trusted proxy configuration and production monitoring are operator responsibilities |
| XML injection | Defused XML parsing; entity expansion rejected | WS-Security signing/encryption is not implemented |
| Injection | ORM bound parameters; structured schemas | No external penetration test claim |
| Secret leakage | No raw request/response bodies in request logs | One-time credentials are necessarily visible to the creating administrator |

## Data handling and operations

Only synthetic data belongs in this environment. Keep database files, environment files and backups private. A database backup contains personal profiles, password hashes and credential metadata, so encrypt backups with an operator-controlled mechanism. Built-in encrypted backup management and KMS integration are not supplied.

Disabling or locking a user blocks subsequent authorized access. Role changes are evaluated on subsequent requests. Revoked clients and tokens cannot authorize further integration calls. Expired or deleted identities must not regain access merely because their browser still holds a cookie.

SCIM `active` represents account activation. Locked state and banking permissions are not silently inserted into the SCIM core schema. Supported filters and PATCH paths are intentionally narrower than the entire RFC grammar; unsupported expressions must return SCIM errors. Bulk support is not advertised.

Audit records share the local database with application state. A database administrator can modify them. Ship records to an independently protected audit sink before relying on them for regulated evidence.

Before any non-local deployment: configure TLS and secure cookies, rotate installation credentials, limit network access, review CORS and proxy headers, run dependency scanning, test restore procedures and complete an independent security review. These are deployment requirements, not claims already fulfilled by the local demonstration.

## Latest verification

On 25 October 2026, the Python 3.12 release container passed 27 integration and security regression tests, including shared-state checks for the added adapters, native gRPC authorization and signed webhook delivery. `pip-audit` reported no known vulnerabilities in the resolved Python environment, and `npm audit --omit=dev` reported none in the production frontend dependency tree. The live PostgreSQL workflow also passed. These are point-in-time advisory and behavior checks; they do not prove the absence of unknown vulnerabilities or replace an independent penetration test.
