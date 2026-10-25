# Capability matrix

Identity API Lab implements interoperable profiles over one canonical identity and access model. “Implemented profile” means the listed paths and behaviors are tested; it does not mean every optional feature of the named standard is present.

## Protocols and transports

| Adapter | Status | Implemented profile |
|---|---|---|
| REST | Implemented | User CRUD/disable, role assignment, effective permissions, role/group reads |
| SCIM 2.0 | Implemented subset | Users, Groups, discovery, paging, selected filters and profile/active PATCH |
| SCIM 1.1 | Implemented subset | User list/read/create/replace/patch/disable with legacy schema URNs |
| SOAP 1.1 | Implemented subset | WSDL and explicit user lifecycle operations |
| SOAP 1.2 | Implemented subset | Same operations with SOAP 1.2 envelope/content handling |
| GraphQL | Implemented subset | User/access queries plus active-state and role-assignment mutations |
| OData 4.0 | Implemented subset | Metadata, Users collection/entity, `$select`, bounded `$filter`, `$top`, `$skip`, `$count`, create/update/delete |
| gRPC | Implemented profile | Native HTTP/2 service defined in `backend/identity.proto`; list/get/create/update/disable |
| JSON-RPC 2.0 | Implemented profile | Single and bounded batch requests for user list/get/create/update/disable |
| Webhooks | Implemented profile | Admin subscriptions, event matching, test delivery, lifecycle delivery, HMAC-SHA256 signing and delivery evidence |
| CSV | Implemented profile | Bounded identity export/import with fixed headers and canonical validation |
| SFTP | Implemented profile | Connector test plus CSV push/pull, encrypted credential storage, host-key pinning and safe remote paths |

XML-RPC, LDAP and JDBC are outside this release. The runtime schema, WSDL, protobuf file and discovery responses are the authoritative integration contracts.

## Authentication and federation

| Capability | Status | Boundary |
|---|---|---|
| OAuth 2.0 Client Credentials | Implemented | Scoped, expiring, revocable opaque access tokens |
| Authorization Code + PKCE | Implemented | S256, exact redirect, one-time short-lived code |
| API key | Implemented | Header credential, hashed at rest, scoped and revocable |
| HTTP Basic | Implemented | Client ID/secret; TLS required outside local use |
| HTTP Digest | Implemented | qop=auth with short-lived signed nonces |
| JWT bearer | Implemented | Lab-issued HS256 token, issuer/audience/expiry and credential-version checks |
| HMAC request signing | Implemented | Method/path/time/nonce/body binding and replay rejection |
| Browser sessions | Implemented | HttpOnly cookie, CSRF on mutations, server-side state and account checks |
| Upstream OIDC | Implemented | Entra, Okta and generic OIDC; state, nonce, PKCE, JWKS validation, mapping, correlation and optional JIT |
| SAML 2.0 | Configuration only | SP metadata is generated; assertion consumer rejects assertions until a trusted verification adapter is installed |
| OAuth refresh/device/token exchange | Not implemented | No unsupported grant claim |
| mTLS, OAuth 1.0, Hawk, SigV4 | Not implemented | Requires provider or transport infrastructure |
| MFA/passkeys | Not implemented | Local password or configured upstream OIDC login |

## Shared authorization

- Per-client scope and protocol allow-lists.
- Per-client readable and writable identity attributes.
- Custom permissions, roles and groups.
- Effective access from direct roles and group grants.
- Server-side operation and object checks.
- Permission-derived banking modules and actions.
- Maker/checker separation, eligible approver routing and atomic synthetic posting.
- Immediate client, token and session revocation.

## Operation coverage

| Operation | REST | SCIM 2 | SCIM 1.1 | SOAP | GraphQL | OData | gRPC | JSON-RPC | CSV/SFTP |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| List/read users | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| Create user | Yes | Yes | Yes | Yes | No | Yes | Yes | Yes | Yes |
| Update profile | Yes | Limited | Limited | Limited | No | Yes | Yes | Yes | Import |
| Enable/disable | Yes | Yes | Yes | Yes | Yes | Delete/patch profile | Yes | Yes | Import |
| Delete/soft-delete | Yes | Yes | Yes | Yes | No | Yes | Disable | Disable | No |
| Assign roles | Yes | No | No | No | Yes | No | No | No | No |
| Effective permissions | Yes | No | No | No | Yes | No | No | No | No |

## Data and user interface

- 15 fictional employees across 15 countries, realistic jobs, departments, roles and groups.
- Six fictional customers and accounts, seeded transactions and pending approvals.
- Command Center with traffic, latency, error, calendar, geographic, organization, session and risk views.
- Authentication Studio, Protocol Management, Request Explorer, Identity Directory, Access & Entitlements, Audit Trail and permission-aware Banking Portal.
- Administrative user preview records the switch and preserves a visible restoration path.

## Known limits

The database uses a compact typed-record store suited to a lab, not a normalized high-concurrency banking schema. Request Explorer records safe metadata rather than complete bodies or distributed traces. Rate limits are process-local. Webhook delivery is synchronous and retry scheduling is not implemented. SFTP is password-based with a pinned host key. SCIM filtering/PATCH, OData query options, SOAP operations and GraphQL schema are intentional subsets. Accessibility and standards behavior have regression coverage but no external certification. Public hosting requires TLS, secret management, backups, centralized evidence, platform rate limits and an independent security assessment.
