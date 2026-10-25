# High-level design

## Purpose

Identity API Lab gives developers and IAM teams one disposable environment where multiple integration protocols, authentication methods and a permission-aware business application operate on the same identity state.

## Context

```mermaid
flowchart TB
  Admin[Lab administrator] --> Web[Web application]
  Employee[Bank employee] --> Web
  Connector[IAM / API connector] --> HTTP[HTTP protocol edge]
  GRPC[gRPC client] --> GRPCEdge[gRPC edge]
  IdP[Entra ID / Okta / OIDC provider] --> Federation[Federation callbacks]
  HTTP --> Core[Identity API Lab core]
  GRPCEdge --> Core
  Web --> Core
  Federation --> Core
  Core --> Database[(Canonical database)]
  Core --> Hook[Signed webhook receivers]
  Core --> SFTP[SFTP server]
```

## Containers and ports

```mermaid
flowchart LR
  Browser -->|HTTP 8787| App[Application container\nReact + FastAPI]
  Client -->|gRPC 50051| App
  App -->|SQL 5432| DB[(PostgreSQL container)]
  App -->|HTTPS| IdP[Optional upstream IdP]
  App -->|HTTPS + HMAC| Receiver[Optional webhook receiver]
  App -->|SSH/SFTP| FileHost[Optional SFTP host]
```

The standard Docker setup exposes HTTP and gRPC only on loopback. PostgreSQL is private to the Compose network. MySQL and SQLite variants preserve the same application contract.

## Major components

| Component | Responsibility |
|---|---|
| React application | Command Center, Authentication Studio, protocol management, request explorer, directory, access administration, banking portal and audit views |
| HTTP edge | Routing, request limits, security headers, request IDs, timing and error normalization |
| Authentication | Browser sessions, client credentials, PKCE, API key, Basic, Digest, JWT and HMAC verification |
| Authorization | Client scopes, permitted protocols, attribute read/write policy, permissions, maker/checker and object checks |
| Protocol adapters | Translate protocol-specific requests into canonical domain operations and serialize results |
| Domain services | Identity lifecycle, role/group access, payments, sessions, clients, federation and evidence |
| Persistence | Typed JSON records through SQLAlchemy on PostgreSQL, MySQL or SQLite |
| Integration egress | Signed webhooks, OIDC discovery/token calls and pinned-key SFTP transfers |
| Observability | Request metadata, authentication result, duration, correlation and immutable-style business audit entries |

## Trust boundaries

```mermaid
flowchart LR
  Public[Untrusted client] --> Edge[Validation and rate limits]
  Edge --> Auth[Credential verification]
  Auth --> Policy[Scope, operation, object and attribute policy]
  Policy --> Domain[Validated domain service]
  Domain --> Store[(Trusted data store)]
  Domain --> Egress[Restricted outbound integration]
```

Secrets are accepted only through headers or request bodies, redacted from stored request metadata and hashed or encrypted at rest. Public deployment requires TLS termination and managed secret storage.

## Availability and scale

The release favors a small footprint and local reproducibility. It runs as one stateless application process plus a database. Multiple HTTP replicas require a shared database and externally coordinated rate limiting; the native gRPC listener requires a platform that exposes TCP. Large, high-availability or regulated deployments need database migrations, external observability, secret management, backups, load tests and an independent security review.

## Key quality attributes

- **Consistency:** all protocol adapters commit to and read from one canonical store.
- **Security:** every operation passes authentication, protocol, scope, attribute and business policy checks.
- **Traceability:** request IDs correlate transport activity with identity and banking audit events.
- **Portability:** Docker Compose supports PostgreSQL, MySQL and SQLite profiles.
- **Testability:** synthetic global data and deterministic APIs allow repeatable lifecycle scenarios.
