# UI inventory and acceptance boundary

The admin studio and Meridian Finance Demo share authentication and canonical identity state. Administrative navigation is under `/admin/*`; the employee experience is `/bank`. The initial implementation uses focused pages and modal details; it does not contain every dedicated screen in the master specification.

## Shared interaction specification

Pages use a collapsible navigation rail, breadcrumb toolbar, light/dark theme, refresh action and a keyboard command palette. Tables scroll inside their own containers. Search filters the currently loaded local records. Loading uses a visible progress indicator; empty collections explain that future activity will appear. Failures display server messages in an alert; success actions display a status toast. Forms have labels, buttons expose focus styling, and dialogs close with Escape. Network failures remain visible until dismissed or retried with Refresh.

The layout adapts to narrower screens, but desktop is the primary administration experience. Dialog focus trapping, screen-reader workflows, every contrast combination, large datasets and complete WCAG 2.2 AA auditing must be validated separately. A functional HTTP test does not prove the UI's accessibility.

## Implemented screen inventory

| Screen / route | User and purpose | Inputs, columns and working actions | Server interaction | Acceptance |
|---|---|---|---|---|
| Sign in | Employee/admin session | Username, password; validation and error feedback | `POST /auth/login` | Valid seeded user enters permitted workspace; invalid credentials rejected |
| Command center `/admin/overview` | Administrator overview | Identity/client/request totals, measured mean duration, protocol status, recent requests, tips | `/admin-api/dashboard` | Counts change after actual operations; no fabricated traffic |
| Identity directory `/admin/users` | Identity administration | Search; profile/status/location data; create, inspect, update, reset password and soft delete | `/admin-api/users`, roles and groups | Save persists across protocol reads; disable blocks next login |
| Identity dialog | Create/edit employee | Username, name, email, department, job, country, city, status and role fields as exposed; required values validated server-side | User create/update/reset/delete | Duplicate username rejected; unauthorized property mutations rejected |
| Access & entitlements `/admin/access` | Review assignments | Roles, groups and selected identity permissions | `/admin-api/users`, `/roles`, `/groups` | Effective access reflects direct and group roles |
| Protocol management `/admin/protocols` | API administration | REST, SCIM, SOAP 1.1/1.2, GraphQL cards; independent availability switches | `/admin-api/protocols` | Disabling REST preserves SCIM and administrative access |
| Authentication studio `/admin/auth` | Client/session/token administration | Select OAuth 2.0, API key and/or HTTP Basic; client name and scope selection; one-time credentials; live method workbench; rotate/revoke | `/admin-api/clients`, `/oauth/token`, `/sessions`, `/tokens`, integration routes | Revoked credentials fail immediately; secrets absent from list/log responses |
| API playground `/admin/playground` | Connector experimentation | Method, local path, headers/body/token fields as exposed; real send and response inspection | Same-origin integration routes | Actual request appears in Request Explorer |
| Request explorer `/admin/requests` | Inspect API behavior | Search, method/path, protocol, status, duration, actor, timestamp; detail modal | `/admin-api/requests` | Inspect the same correlation ID as audit changes |
| Request detail | Diagnose one request | Summary, authentication, audit and raw metadata tabs | `/admin-api/requests/{id}` | No invented spans or captured secrets |
| Audit trail `/admin/audit` | Review user/configuration changes | Search and expandable actor/action/target/time/change records | `/admin-api/audit` | Lifecycle and credential actions appear with request correlation |
| Documentation `/admin/docs` | Complete integration and cURL reference | Searchable copy-ready cURL examples for authentication, REST, SCIM, GraphQL, SOAP, administration and evidence; OpenAPI/WSDL links | Protocol inventory, `/openapi.json`, `/soap?wsdl` | Examples match live routes and identify placeholders explicitly |
| Settings & About `/admin/settings` | Environment details and authorship | Database/capability information, copy, Dinesh story, searchable engineering tips | `/admin-api/settings` | Database is reported, not silently switched |
| Banking overview `/bank` | Employee workspace | Permitted counts and effective permission labels | `/banking/dashboard` | Viewer has read modules; disabled account rejected |
| Customers and accounts | Authorized read | Synthetic rows and detail dialogs | `/banking/customers`, `/banking/accounts` | Server denies missing permission even with a direct request |
| Transactions | Authorized synthetic history | Read table and detail dialog | `/banking/transactions` | Approved payment creates history |
| Payments and approvals | Maker/checker simulation | Source/destination/amount/reference, create and approve with confirmation | `/banking/payments` | Maker cannot self-approve; second approval conflicts; balances update once |
| My profile | Current user details | Read-only profile dialog, sign out | Session identity, `/auth/logout` | Logout ends access |

## Design tokens and component catalog

The frontend stylesheet defines semantic background, surface, border, text, accent, success and error tokens for both themes. Operational controls use icons plus text/status labels. Reusable components include badges, empty states, search fields, modal dialogs, request tables, generic data tables, form controls and status alerts. Icons come from the declared frontend package; no external product branding is copied.

This inventory documents the delivered page structure and its interaction boundaries.

## Planned screens and workflows

Dedicated credential vault/detail, collection persistence, distributed tracing, scenario fault injection, database setup wizard, external connection testing, notification center and configurable environment switching remain future work. No button should present these as a functioning capability.
