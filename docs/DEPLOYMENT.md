# Installation and deployment

## Local installation

Docker Desktop or Docker Engine with Compose v2 is the only prerequisite.

Windows:

```powershell
.\scripts\lab.ps1 install
```

macOS or Linux:

```sh
sh scripts/lab.sh install
```

PostgreSQL is the default. Select another database with `-Database mysql` or
`-Database sqlite` on Windows, or `sh scripts/lab.sh install mysql` on macOS and
Linux. The installer generates independent administrator, demo, database and
server-signing secrets, selects an available local port, builds the application,
waits for health checks and verifies the running version.

The same tool supports `start`, `stop`, `restart`, `status`, `logs`, `verify`,
`passwords` and `update`. `passwords` deliberately requires a direct command so
credentials are not printed in ordinary installation logs.

## Railway deployment

The repository includes `railway.json` and a production Dockerfile. In Railway,
create a project from the GitHub repository, add PostgreSQL, then configure
`DATABASE_URL`, `ADMIN_PASSWORD`, `DEMO_PASSWORD`, `SERVER_SIGNING_KEY`,
`PUBLIC_URL`, `ALLOWED_HOSTS` and `COOKIE_SECURE=true`. Generate long random
values for every secret and set `PUBLIC_URL` to the assigned HTTPS domain.

Railway exposes the HTTP service through its generated domain. Native gRPC needs
a separate public TCP endpoint or private-network client access. Keep the
database service private. A reusable public Railway template additionally
requires publishing the configured project from the Railway dashboard after the
first successful deployment.

## Render blueprint

The repository includes `render.yaml`. After the project is published to GitHub,
add Render's deploy button to the README using the final repository URL. Each
developer can deploy an independent web service and PostgreSQL database into
their own Render account. Render generates the application secrets.

The blueprint disables automatic deployment. A developer reviews and explicitly
deploys updates in their own account. Set the public service URL as `PUBLIC_URL`
when configuring external OIDC callbacks.

## Public VPS or server

Keep PostgreSQL private. Put the application behind a TLS reverse proxy, then set:

```text
APP_BIND=0.0.0.0
PUBLIC_URL=https://lab.example.com
COOKIE_SECURE=true
ALLOWED_HOSTS=lab.example.com
```

Restrict inbound traffic to ports 80/443, back up the database volume, rotate all
generated credentials, and do not publish `.env`. The demonstration data and
banking operations are synthetic and are not designed for production banking.
Private or plain-HTTP SSO endpoints remain disabled unless an operator explicitly
sets `ALLOW_PRIVATE_SSO=true` or `ALLOW_INSECURE_SSO=true` for a controlled local
test environment.

## Hosted product architecture

For a paid service, run a small control plane that manages signup, billing,
tenant lifecycle and limits. Provision one isolated application/database pair per
customer at first. This gives customers clean test data and strong isolation and
is simpler to support than adding shared-database multi-tenancy to the current
lab. Suspend idle trial environments and retain paid environments according to a
published retention policy.

Recommended plans:

- Free: time-limited shared demonstration with resettable data.
- Developer: one persistent isolated lab.
- Team: several environments, team access and longer audit retention.
- Enterprise: dedicated environment, custom domain, SSO setup assistance and
  support.

Never accept real bank customer data. Add account verification, quotas, abuse
controls, billing webhooks, backups, tenant deletion, support access controls and
service monitoring before operating a public service.
