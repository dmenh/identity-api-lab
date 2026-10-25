"""Repeatable live acceptance check for an installed Identity API Lab."""
import json, os, secrets
from http.cookiejar import CookieJar
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, build_opener, HTTPCookieProcessor

ROOT = os.getenv("LAB_URL", "http://localhost:8787").rstrip("/")
# Some Windows security products inject a non-filesystem SSL keylog target. The
# verifier does not need TLS key logging and removes it before urllib builds SSL.
os.environ.pop("SSLKEYLOGFILE", None)


def env_file():
    result = {}
    with open(os.path.join(os.path.dirname(__file__), "..", ".env"), encoding="utf-8") as source:
        for line in source:
            if "=" in line and not line.lstrip().startswith("#"):
                key, value = line.strip().split("=", 1)
                result[key] = value
    return result


class Session:
    def __init__(self):
        self.opener = build_opener(HTTPCookieProcessor(CookieJar()))
        self.csrf = None

    def call(self, method, path, body=None, headers=None, expected=(200,)):
        headers = dict(headers or {})
        if self.csrf and method not in ("GET", "HEAD"):
            headers.setdefault("X-CSRF-Token", self.csrf)
        if body is not None and not isinstance(body, bytes):
            body = json.dumps(body).encode()
            headers.setdefault("Content-Type", "application/json")
        request = Request(ROOT + path, data=body, method=method, headers=headers)
        try:
            response = self.opener.open(request, timeout=15)
            status, raw, response_headers = response.status, response.read(), response.headers
        except HTTPError as error:
            status, raw, response_headers = error.code, error.read(), error.headers
        if status not in expected:
            raise AssertionError(f"{method} {path}: expected {expected}, received {status}: {raw[:500]!r}")
        value = json.loads(raw) if raw and "json" in response_headers.get("content-type", "") else raw.decode()
        return status, value, response_headers

    def login(self, username, password):
        _, data, _ = self.call("POST", "/auth/login", {"username": username, "password": password})
        self.csrf = data["csrfToken"]
        return data


def main():
    config = env_file()
    admin = Session()
    admin.login("admin", config["ADMIN_PASSWORD"])
    _, health, headers = admin.call("GET", "/health")
    assert health["version"] == "1.5.0"
    assert headers.get("X-Content-Type-Options") == "nosniff"

    suffix = secrets.token_hex(4)
    _, client, _ = admin.call("POST", "/admin-api/clients", {
        "name": "Live attribute check " + suffix,
        "scopes": ["users:read", "users:write"],
        "protocols": ["rest", "scim", "scim11", "soap11", "soap12", "graphql", "odata", "grpc", "jsonrpc", "webhooks", "csvsftp"],
        "authenticationMethods": ["oauth2_client_credentials"],
        "readAttributes": ["username", "email"],
        "writeAttributes": ["displayName"],
    }, expected=(201,))
    form = urlencode({"grant_type": "client_credentials", "client_id": client["clientId"], "client_secret": client["clientSecret"], "scope": "users:read users:write"}).encode()
    _, token, _ = admin.call("POST", "/oauth/token", form, {"Content-Type": "application/x-www-form-urlencoded"})
    bearer = {"Authorization": "Bearer " + token["access_token"]}
    _, users, _ = admin.call("GET", "/api/v1/users", headers=bearer)
    assert users and set(users[0]).issubset({"id", "username", "email"})
    _, scim11, _ = admin.call("GET", "/scim/v1/Users?count=2", headers=bearer)
    assert scim11["totalResults"] >= 15
    _, odata, _ = admin.call("GET", "/odata/v4/Users?$top=2&$select=id,username,email", headers=bearer)
    assert len(odata["value"]) == 2
    _, rpc, _ = admin.call("POST", "/jsonrpc", {"jsonrpc": "2.0", "id": 1, "method": "users.list", "params": {"count": 2}}, bearer)
    assert rpc["jsonrpc"] == "2.0" and len(rpc["result"]) >= 2
    _, csv_export, _ = admin.call("GET", "/api/v1/csv/users", headers=bearer)
    header = csv_export.splitlines()[0].split(",")
    assert header[:2] == ["id", "username"] and "email" in header
    admin.call("PATCH", "/api/v1/users/" + users[0]["id"], {"department": "Denied"}, bearer, expected=(403,))

    permission_key = "LIVE_" + suffix.upper()
    admin.call("POST", "/admin-api/permissions", {"id": permission_key, "name": "Live verification"}, expected=(201,))
    _, role, _ = admin.call("POST", "/admin-api/roles", {"name": "Live verifier " + suffix, "permissions": [permission_key]}, expected=(201,))
    _, group, _ = admin.call("POST", "/admin-api/groups", {"displayName": "Live group " + suffix, "roles": [role["id"]], "members": []}, expected=(201,))
    admin.call("PATCH", "/admin-api/groups/" + group["id"], {"displayName": "Updated live group " + suffix})

    _, dashboard, _ = admin.call("GET", "/admin-api/dashboard")
    feeds = {"timeline", "protocols", "authentication", "calendar", "countries", "departments", "userHealth", "sessions", "risk"}
    assert feeds.issubset(dashboard["charts"]) and len(dashboard["charts"]["timeline"]) == 12

    _, provider, _ = admin.call("POST", "/admin-api/sso-providers", {
        "name": "Live Entra " + suffix, "type": "oidc", "preset": "entra",
        "issuer": "https://login.microsoftonline.com/example/v2.0",
        "authorizationEndpoint": "https://login.microsoftonline.com/example/oauth2/v2.0/authorize",
        "tokenEndpoint": "https://login.microsoftonline.com/example/oauth2/v2.0/token",
        "jwksUri": "https://login.microsoftonline.com/example/discovery/v2.0/keys",
        "clientId": "live-client", "clientSecret": "must-not-leak", "enabled": True,
        "jitProvisioning": True, "defaultRoles": ["viewer"], "correlationAttribute": "email",
        "claimMapping": {"username": "preferred_username", "email": "email", "displayName": "name", "firstName": "given_name", "lastName": "family_name", "department": "extension.department", "jobTitle": "job_title", "country": "country", "city": "city"},
    }, expected=(201,))
    assert "clientSecret" not in provider and "clientSecretEncrypted" not in provider
    assert provider["claimMapping"]["department"] == "extension.department" and provider["correlationAttribute"] == "email"
    _, public_providers, _ = admin.call("GET", "/sso/providers")
    assert any(row["id"] == provider["id"] for row in public_providers)
    admin.call("DELETE", "/admin-api/sso-providers/" + provider["id"], expected=(204,))

    _, directory, _ = admin.call("GET", "/admin-api/users")
    operator = next(row for row in directory if row["username"] == "liam.johnson")
    maker = Session()
    maker.login(operator["username"], config["DEMO_PASSWORD"])
    _, accounts, _ = maker.call("GET", "/banking/accounts")
    _, payment, _ = maker.call("POST", "/banking/payments", {"fromAccountId": accounts[0]["id"], "toAccountId": accounts[1]["id"], "amount": "17.25", "reference": "Live acceptance " + suffix}, expected=(201,))
    approver = next(row for row in directory if row["id"] == payment["assignedApproverId"])
    checker = Session()
    checker.login(approver["username"], config["DEMO_PASSWORD"])
    _, approved, _ = checker.call("POST", "/banking/payments/" + payment["id"] + "/approve")
    assert approved["status"] == "Approved" and approved.get("transactionId")
    _, transactions, _ = checker.call("GET", "/banking/transactions")
    assert any(row.get("paymentId") == payment["id"] for row in transactions)

    service_user = next(row for row in directory if row["username"] == "priya.sharma")
    service = Session()
    service.login(service_user["username"], config["DEMO_PASSWORD"])
    _, service_dashboard, _ = service.call("GET", "/banking/dashboard")
    assert set(service_dashboard["permissions"]) != set(checker.call("GET", "/banking/dashboard")[1]["permissions"])
    _, sessions, _ = admin.call("GET", "/admin-api/sessions")
    service_session = next(row for row in sessions if row.get("username") == service_user["username"] and not row["revoked"])
    admin.call("POST", "/admin-api/sessions/" + service_session["id"] + "/revoke")
    service.call("GET", "/banking/dashboard", expected=(401,))

    admin.call("DELETE", "/admin-api/groups/" + group["id"], expected=(204,))
    admin.call("DELETE", "/admin-api/roles/" + role["id"], expected=(204,))
    admin.call("POST", "/admin-api/clients/" + client["id"] + "/revoke")
    print(json.dumps({"status": "passed", "version": health["version"], "chartFeeds": len(dashboard["charts"]), "payment": approved["status"], "transactionRecorded": True, "ssoMappingSaved": True, "sessionTermination": True, "permissionProfilesDiffer": True, "attributePolicyEnforced": True}))


if __name__ == "__main__":
    main()
