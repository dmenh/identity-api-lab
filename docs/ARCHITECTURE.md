# Identity API Lab — architecture and decisions

Designed & Built by Dinesh. Meridian Finance Demo contains synthetic employees and banking records; it does not send payments or connect to a financial institution.

## Product scope

The first delivery is a lightweight, runnable vertical slice of the master specification. Its acceptance boundary is a shared employee lifecycle across REST, SCIM 2.0, SOAP and GraphQL, scoped client credentials, a permission-controlled banking portal, request evidence and immediate revocation. Consult [CAPABILITIES.md](CAPABILITIES.md) for explicit limitations. A page or planned adapter is not evidence of implemented support.

## System and component architecture

```mermaid
flowchart LR
  Browser[Admin studio and banking portal] --> HTTP[FastAPI HTTP application]
  Connector[IAM connector / API client] --> HTTP
  HTTP --> Session[Cookie session + CSRF]
  HTTP --> OAuth[OAuth client credentials / opaque bearer]
  HTTP --> Registry[Independent protocol switches]
  Registry --> REST[REST JSON]
  Registry --> SCIM[SCIM 2.0 adapter]
  Registry --> SOAP[SOAP XML adapter]
  Registry --> GQL[GraphQL schema and resolvers]
  Session --> Policy[Permission and scope checks]
  OAuth --> Policy
  REST --> Domain[Shared identity operations]
  SCIM --> Domain
  SOAP --> Domain
  GQL --> Domain
  Policy --> Domain
  Domain --> ORM[SQLAlchemy database layer]
  ORM --> DB[(SQLite / PostgreSQL / MySQL)]
  HTTP --> Requests[Request metadata]
  Domain --> Audit[Business audit events]
  Requests --> DB
  Audit --> DB
```

The same database state is read by every adapter. There is no asynchronous synchronization queue. A successful committed lifecycle mutation is visible to the next request through other enabled protocols. Protocol switches apply to integration routes; they do not switch off administrative recovery routes.

## Architecture decision records

| Decision | Reason | Consequence |
|---|---|---|
| Modular monolith | One small local deployment and one canonical identity state | No mandatory Redis, Kafka or Kubernetes |
| FastAPI and SQLAlchemy | Small Python service, mature HTTP and parameterized database layer | Python is a deliberate substitute for the suggested TypeScript backend |
| SQLite quick start | Zero database installation for a disposable lab | External PostgreSQL/MySQL remain separate selectable deployments; portability requires running tests on each |
| Server-side opaque tokens | Direct expiry and revocation checks with no signing-key infrastructure | No JWT/JWKS/audience-signature feature claim |
| Cookie portal sessions | HttpOnly credentials and CSRF checks on mutations | Production deployment must enforce TLS and secure-cookie settings |
| Request metadata only | Avoid storing secrets and personal request bodies | Request Explorer cannot reproduce full request/response payloads or accurate per-stage timing |
| Shared authorization | Banking and APIs enforce permission/scope checks on the server | UI visibility complements server enforcement |

## Logical data model

This is the logical relationship diagram. The initial physical database uses a single `lab_records` table with a primary key, indexed record kind and JSON text body; associations are collections of identifiers in those records. Application code validates references. It does not provide the master's normalized tables, database foreign keys, database-enforced username uniqueness or concurrent-update guarantees. The compact representation reduces setup complexity but requires a future normalized migration for large or concurrent deployments. The generated database schema is authoritative for physical tables and constraints.

```mermaid
erDiagram
  USER }o--o{ ROLE : assigned
  USER }o--o{ GROUP : member
  GROUP }o--o{ ROLE : grants
  ROLE }o--o{ PERMISSION : grants
  USER ||--o{ SESSION : owns
  CLIENT ||--o{ TOKEN : receives
  USER ||--o{ AUDIT_EVENT : target
  REQUEST_LOG ||--o{ AUDIT_EVENT : correlation
  CUSTOMER ||--o{ BANK_ACCOUNT : owns
  BANK_ACCOUNT ||--o{ PAYMENT : source
  USER ||--o{ PAYMENT : creates
  USER ||--o{ PAYMENT : approves
  PROTOCOL ||--o{ REQUEST_LOG : routes
```

## OAuth client credentials flow

```mermaid
sequenceDiagram
  actor Admin
  participant Client
  participant App
  participant DB
  Admin->>App: Register client and allowed scopes
  App->>DB: Persist client secret hash
  App-->>Admin: Client ID and one-time secret
  Client->>App: POST /oauth/token with client authentication and scopes
  App->>DB: Validate client, secret and permitted scopes
  App-->>Client: Opaque access token, expiry and scope
  Client->>App: Bearer token on protocol request
  App->>DB: Check token expiry, revocation and client state
  App->>App: Check operation scope / user permissions
  App-->>Client: Protocol response + request identifier
```

## Lifecycle and session invalidation

```mermaid
sequenceDiagram
  participant Connector
  participant API
  participant DB
  participant Portal
  Connector->>API: SCIM create employee
  API->>DB: Persist employee and audit event
  Connector->>API: REST assign Viewer role
  API->>DB: Update role assignment
  Connector->>API: GraphQL effectivePermissions
  API-->>Connector: Current calculated permissions
  Portal->>API: Sign in and request banking dashboard
  API-->>Portal: Permitted modules and synthetic records
  Connector->>API: SOAP DisableUser
  API->>DB: Disable employee / revoke sessions
  Portal->>API: Next authenticated operation
  API-->>Portal: Access rejected
```

## Credential rotation

```mermaid
sequenceDiagram
  actor Admin
  participant App
  participant Client
  Admin->>App: Rotate client secret
  App->>App: Replace secret hash and revoke prior tokens
  App-->>Admin: New secret shown once
  Client->>App: Use old token or old secret
  App-->>Client: Reject
  Client->>App: Authenticate with new secret
  App-->>Client: New scoped token
```

## Authorization and observability

```mermaid
flowchart TD
  A[Incoming HTTP request] --> B{Protocol enabled?}
  B -->|No| Reject[Controlled rejection]
  B -->|Yes| C[Resolve explicit bearer or portal session]
  C --> D{Valid and unexpired?}
  D -->|No| Reject
  D -->|Yes| E{Scope or operation permission?}
  E -->|No| Reject
  E -->|Yes| F{Object and business rules?}
  F -->|No| Reject
  F -->|Yes| G[Validated domain mutation / read]
  G --> H[Commit data and business audit]
  H --> I[Protocol serialization]
  I --> J[Record total duration and outcome]
  Reject --> J
```

Request IDs and correlation IDs connect HTTP metadata to business audit events. Total HTTP duration is measured; no invented timing spans are presented as instrumented measurements. Metrics are derived from stored requests. Logs are local lab records, not a tamper-proof external audit store.
