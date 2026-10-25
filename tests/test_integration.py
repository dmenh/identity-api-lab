"""Cross-protocol acceptance and security regression tests against the real app."""
import uuid
import base64
import hashlib
import hmac
import time
from urllib.parse import urlparse, parse_qs
import httpx
import xml.etree.ElementTree as ET
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import grpc
from google.protobuf.struct_pb2 import Struct
from google.protobuf.json_format import MessageToDict

SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
ALL_SCOPES = ["users:read", "users:write", "roles:read", "roles:write", "groups:read", "groups:write", "banking:read", "banking:write"]


def unique(prefix="employee"):
    return prefix + uuid.uuid4().hex[:10]


def oauth(admin, scopes=None):
    scopes = ALL_SCOPES if scopes is None else scopes
    response = admin.post("/admin-api/clients", json={"name": unique("integration"), "scopes": scopes})
    assert response.status_code in (200, 201), response.text
    registered = response.json()
    token = admin.post("/oauth/token", data={"grant_type": "client_credentials", "client_id": registered["clientId"], "client_secret": registered["clientSecret"], "scope": " ".join(scopes)})
    assert token.status_code == 200, token.text
    return registered, {"Authorization": "Bearer " + token.json()["access_token"]}


def scim_user(admin, headers, **extra):
    data = {"schemas": [SCHEMA], "userName": unique(), "displayName": "Integration Employee", "password": "Employee-Test-2026!", "active": True}
    data.update(extra)
    result = admin.post("/scim/v2/Users", json=data, headers=headers)
    assert result.status_code == 201, result.text
    return result.json()


def soap(operation, fields="", version="1.1"):
    namespace = "http://schemas.xmlsoap.org/soap/envelope/" if version == "1.1" else "http://www.w3.org/2003/05/soap-envelope"
    return f'<s:Envelope xmlns:s="{namespace}" xmlns:i="urn:identity-api-lab"><s:Body><i:{operation}>{fields}</i:{operation}></s:Body></s:Envelope>'


def test_eight_step_cross_protocol_identity_lifecycle(admin):
    # 1. All adapters simultaneously enabled, through the management API.
    for protocol in ["rest", "scim", "soap11", "soap12", "graphql"]:
        assert admin.patch(f"/admin-api/protocols/{protocol}", json={"enabled": True}).status_code == 200
    # 2. Registered confidential client receives a scoped token.
    registered, headers = oauth(admin)
    # 3. A genuine SCIM resource is created in the canonical database.
    person = scim_user(admin, headers)
    user_id = person["id"]
    assert SCHEMA in person["schemas"]
    assert person["active"] is True
    # 4. REST grants Viewer; GraphQL computes the resulting permissions.
    roles = admin.get("/api/v1/roles", headers=headers).json()
    viewer = next(role for role in roles if role["name"] == "Viewer")
    assigned = admin.put(f"/api/v1/users/{user_id}/roles", json={"roles": [viewer["id"]]}, headers=headers)
    assert assigned.status_code == 200, assigned.text
    query = admin.post("/graphql", headers=headers, json={"query": "query($id: ID!) { effectivePermissions(userId: $id) }", "variables": {"id": user_id}})
    assert query.status_code == 200, query.text
    assert "errors" not in query.json(), query.text
    assert "CUSTOMER_READ" in query.json()["data"]["effectivePermissions"]
    # 5. Banking session is permission controlled at the server.
    admin.cookies.clear()
    login = admin.post("/auth/login", json={"username": person["userName"], "password": "Employee-Test-2026!"})
    assert login.status_code == 200, login.text
    admin.headers["X-CSRF-Token"] = login.json()["csrfToken"]
    dashboard = admin.get("/banking/dashboard")
    assert dashboard.status_code == 200, dashboard.text
    assert "CUSTOMER_READ" in dashboard.json()["permissions"]
    denied = admin.post("/banking/payments", json={"fromAccountId": "forbidden", "toAccountId": "forbidden", "amount": 10, "reference": "must fail"})
    assert denied.status_code == 403, denied.text
    # 6. SOAP disables the same resource and invalidates the banking session.
    disabled = admin.post("/soap", content=soap("DisableUser", f"<userId>{user_id}</userId>"), headers={**headers, "Content-Type": "text/xml"})
    assert disabled.status_code == 200, disabled.text
    ET.fromstring(disabled.text)
    assert admin.get(f"/api/v1/users/{user_id}", headers=headers).json()["active"] is False
    assert admin.get(f"/scim/v2/Users/{user_id}", headers=headers).json()["active"] is False
    result = admin.post("/graphql", headers=headers, json={"query": "query($id: ID!) { user(id: $id) { id active } }", "variables": {"id": user_id}})
    assert result.json()["data"]["user"]["active"] is False
    assert admin.get("/banking/dashboard").status_code in (401, 403)
    assert admin.post("/auth/login", json={"username": person["userName"], "password": "Employee-Test-2026!"}).status_code in (401, 403)
    # 7. Real request evidence and audit changes are available to administrators.
    login = admin.post("/auth/login", json={"username": "admin", "password": "Lab-Test-2026!"})
    admin.headers["X-CSRF-Token"] = login.json()["csrfToken"]
    requests = admin.get("/admin-api/requests").json()
    relevant = [row for row in requests if row["path"].startswith(("/scim/", "/soap", "/graphql", "/api/v1/"))]
    assert relevant
    assert all(row["durationMs"] >= 0 for row in relevant)
    assert any(row["path"] == "/soap" and row["status"] == 200 for row in relevant)
    audit = admin.get("/admin-api/audit").json()
    assert any(row["targetId"] == user_id for row in audit)
    assert registered["clientSecret"] not in str(requests) + str(audit)
    assert headers["Authorization"] not in str(requests) + str(audit)
    # 8. Client revocation invalidates previously issued tokens immediately.
    assert admin.post(f'/admin-api/clients/{registered["id"]}/revoke').status_code == 200
    assert admin.get("/api/v1/users", headers=headers).status_code == 401


def test_protocol_switches_are_independent(admin):
    _, headers = oauth(admin)
    try:
        assert admin.patch("/admin-api/protocols/rest", json={"enabled": False}).status_code == 200
        assert admin.get("/api/v1/users", headers=headers).status_code == 503
        assert admin.get("/scim/v2/Users", headers=headers).status_code == 200
        assert admin.get("/admin-api/protocols").status_code == 200
    finally:
        admin.patch("/admin-api/protocols/rest", json={"enabled": True})


def test_missing_scopes_and_invalid_bearer_cannot_fall_back_to_admin_cookie(admin):
    _, headers = oauth(admin, ["users:read"])
    assert admin.get("/api/v1/users", headers=headers).status_code == 200
    result = admin.post("/api/v1/users", headers=headers, json={"username": unique(), "password": "Employee-Test-2026!"})
    assert result.status_code == 403, result.text
    assert admin.get("/api/v1/users", headers={"Authorization": "Bearer invalid"}).status_code == 401


def test_unauthenticated_and_csrf_rejected(client):
    assert client.get("/api/v1/users").status_code == 401
    assert client.get("/admin-api/users").status_code == 401
    assert client.post("/auth/login", json={"username": "admin", "password": "wrong"}).status_code == 401
    assert client.post("/auth/login", json={"username": "admin", "password": "Lab-Test-2026!"}).status_code == 200
    assert client.patch("/admin-api/protocols/rest", json={"enabled": False}).status_code == 403


def test_oauth_grant_scope_and_secret_validation(admin):
    registered, _ = oauth(admin, ["users:read"])
    form = {"grant_type": "client_credentials", "client_id": registered["clientId"], "client_secret": registered["clientSecret"]}
    assert admin.post("/oauth/token", data={**form, "scope": "users:write"}).status_code == 400
    assert admin.post("/oauth/token", data={**form, "client_secret": "incorrect"}).status_code in (400, 401)
    assert admin.post("/oauth/token", data={**form, "grant_type": "password"}).status_code == 400


def test_selectable_client_authentication_methods_work_end_to_end(admin):
    created = admin.post("/admin-api/clients", json={
        "name": unique("multi-auth"),
        "scopes": ["users:read"],
        "authenticationMethods": ["oauth2_client_credentials", "api_key", "http_basic"],
    })
    assert created.status_code == 201, created.text
    client = created.json()
    assert client["apiKey"].startswith("ial_")
    assert admin.get("/api/v1/users", headers={"X-API-Key": client["apiKey"]}).status_code == 200
    basic = base64.b64encode(f'{client["clientId"]}:{client["clientSecret"]}'.encode()).decode()
    assert admin.get("/api/v1/users", headers={"Authorization": "Basic " + basic}).status_code == 200
    token = admin.post("/oauth/token", data={"grant_type": "client_credentials", "client_id": client["clientId"], "client_secret": client["clientSecret"], "scope": "users:read"})
    assert token.status_code == 200, token.text
    assert admin.get("/api/v1/users", headers={"Authorization": "Bearer " + token.json()["access_token"]}).status_code == 200
    assert admin.get("/api/v1/users", headers={"X-API-Key": "invalid"}).status_code == 401

    key_only = admin.post("/admin-api/clients", json={"name": unique("key-only"), "scopes": ["users:read"], "authenticationMethods": ["api_key"]}).json()
    denied = admin.post("/oauth/token", data={"grant_type": "client_credentials", "client_id": key_only["clientId"], "client_secret": key_only["clientSecret"]})
    assert denied.status_code == 401


def test_extended_authentication_catalog_end_to_end(admin, client):
    methods = ["oauth2_client_credentials", "oauth2_authorization_code_pkce", "api_key", "http_basic", "jwt_bearer", "hmac_sha256", "http_digest"]
    created = admin.post("/admin-api/clients", json={"name": unique("all-auth"), "scopes": ["users:read"], "authenticationMethods": methods, "redirectUris": ["http://testserver/oauth/callback"]})
    assert created.status_code == 201, created.text
    credentials = created.json()

    jwt = client.post("/oauth/jwt", data={"client_id": credentials["clientId"], "client_secret": credentials["clientSecret"], "scope": "users:read"})
    assert jwt.status_code == 200, jwt.text
    assert client.get("/api/v1/users", headers={"Authorization": "Bearer " + jwt.json()["access_token"]}).status_code == 200

    timestamp, nonce = str(int(time.time())), uuid.uuid4().hex
    canonical = "\n".join(["GET", "/api/v1/users", timestamp, nonce, hashlib.sha256(b"").hexdigest()])
    signature = hmac.new(credentials["hmacSecret"].encode(), canonical.encode(), hashlib.sha256).hexdigest()
    signed = client.get("/api/v1/users", headers={"X-Client-ID": credentials["clientId"], "X-Timestamp": timestamp, "X-Nonce": nonce, "X-Signature": signature})
    assert signed.status_code == 200, signed.text
    assert client.get("/api/v1/users", headers={"X-Client-ID": credentials["clientId"], "X-Timestamp": timestamp, "X-Nonce": nonce, "X-Signature": signature}).status_code == 401

    digest_response = client.get("/api/v1/users", auth=httpx.DigestAuth(credentials["clientId"], credentials["digestPassword"]))
    assert digest_response.status_code == 200, digest_response.text

    verifier = base64.urlsafe_b64encode(uuid.uuid4().bytes + uuid.uuid4().bytes).decode().rstrip("=")
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    authorize = admin.get("/oauth/authorize", params={"response_type": "code", "client_id": credentials["clientId"], "redirect_uri": "http://testserver/oauth/callback", "code_challenge": challenge, "code_challenge_method": "S256", "scope": "users:read", "state": "acceptance"}, follow_redirects=False)
    assert authorize.status_code == 302, authorize.text
    code = parse_qs(urlparse(authorize.headers["location"]).query)["code"][0]
    pkce = client.post("/oauth/token", data={"grant_type": "authorization_code", "client_id": credentials["clientId"], "redirect_uri": "http://testserver/oauth/callback", "code": code, "code_verifier": verifier})
    assert pkce.status_code == 200, pkce.text
    assert client.get("/api/v1/users", headers={"Authorization": "Bearer " + pkce.json()["access_token"]}).status_code == 200


def test_rotation_revokes_old_secret_and_existing_tokens(admin):
    registered, headers = oauth(admin)
    rotated = admin.post(f'/admin-api/clients/{registered["id"]}/rotate')
    assert rotated.status_code == 200, rotated.text
    assert rotated.json()["clientSecret"] != registered["clientSecret"]
    assert admin.get("/api/v1/users", headers=headers).status_code == 401
    old = admin.post("/oauth/token", data={"grant_type": "client_credentials", "client_id": registered["clientId"], "client_secret": registered["clientSecret"]})
    assert old.status_code in (400, 401)


def test_scim_patch_filter_and_duplicate(admin):
    _, headers = oauth(admin)
    person = scim_user(admin, headers)
    path = f'/scim/v2/Users/{person["id"]}'
    changed = admin.patch(path, headers=headers, json={"schemas": [PATCH], "Operations": [{"op": "replace", "path": "displayName", "value": "Changed Name"}, {"op": "replace", "path": "active", "value": False}]})
    assert changed.status_code == 200, changed.text
    assert changed.json()["displayName"] == "Changed Name"
    assert changed.json()["active"] is False
    found = admin.get("/scim/v2/Users", headers=headers, params={"filter": f'userName eq "{person["userName"]}"'})
    assert found.status_code == 200, found.text
    assert found.json()["totalResults"] == 1
    duplicate = admin.post("/scim/v2/Users", headers=headers, json={"schemas": [SCHEMA], "userName": person["userName"]})
    assert duplicate.status_code == 409, duplicate.text
    invalid = admin.get("/scim/v2/Users", headers=headers, params={"filter": "invalid filter syntax"})
    assert invalid.status_code == 400, invalid.text
    assert "urn:ietf:params:scim:api:messages:2.0:Error" in invalid.json()["schemas"]


def test_soap_safe_xml_parser_and_real_wsdl(admin):
    _, headers = oauth(admin)
    wsdl = admin.get("/soap?wsdl", headers=headers)
    assert wsdl.status_code == 200, wsdl.text
    root = ET.fromstring(wsdl.text)
    assert root.tag.endswith("definitions")
    malicious = '<!DOCTYPE x [<!ENTITY leak SYSTEM "file:///etc/passwd">]>' + soap("GetUser", "<userId>&leak;</userId>")
    rejected = admin.post("/soap", headers={**headers, "Content-Type": "text/xml"}, content=malicious)
    assert rejected.status_code in (400, 500), rejected.text
    assert "root:x:" not in rejected.text
    assert "Fault" in rejected.text


def test_graphql_field_validation_and_resolver_scope(admin):
    _, headers = oauth(admin, ["users:read"])
    invalid = admin.post("/graphql", headers=headers, json={"query": "{ users { passwordHash } }"})
    assert "errors" in invalid.json()
    assert "Traceback" not in invalid.text
    denied = admin.post("/graphql", headers=headers, json={"query": 'mutation { setUserActive(id:"missing",active:false) { id } }'})
    assert denied.status_code in (200, 403)
    assert "errors" in denied.json() or denied.status_code == 403


def test_graphql_complexity_and_security_headers(admin):
    _, headers = oauth(admin, ["users:read"])
    deep = "{ users { " + "permissions { " * 13 + "id" + " }" * 13 + " } }"
    rejected = admin.post("/graphql", headers=headers, json={"query": deep})
    assert rejected.status_code == 400, rejected.text
    response = admin.get("/health")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cross-origin-opener-policy"] == "same-origin"
    assert "camera=()" in response.headers["permissions-policy"]
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]


def test_untrusted_host_and_private_sso_endpoint_rejected(admin):
    assert admin.get("/health", headers={"Host": "attacker.example"}).status_code == 400
    blocked = admin.post("/admin-api/sso-providers", json={
        "name": "Blocked local IdP", "type": "oidc", "preset": "custom",
        "issuer": "https://127.0.0.1", "clientId": "blocked", "enabled": True,
    })
    assert blocked.status_code == 400, blocked.text


def test_seed_has_fifteen_international_employees(admin):
    users = admin.get("/admin-api/users").json()
    # Additional tests may create identities: the seed is a lower bound here.
    assert len(users) >= 15
    assert len({u["country"] for u in users if u.get("country")}) >= 10
    assert len({u["department"] for u in users if u.get("department")}) >= 5
    assert all("password" not in user and "passwordHash" not in user for user in users)


def test_admin_can_preview_employee_portal_and_restore_session(admin):
    users = admin.get("/admin-api/users").json()
    target = next(user for user in users if user["username"] == "emma.wilson")
    started = admin.post(f'/admin-api/impersonate/{target["id"]}')
    assert started.status_code == 200, started.text
    assert started.json()["user"]["id"] == target["id"]
    assert started.json()["impersonation"]["administrator"]["username"] == "admin"
    me = admin.get("/auth/me")
    assert me.status_code == 200 and me.json()["impersonation"]["active"] is True
    assert admin.get("/banking/dashboard").status_code == 200
    assert admin.get("/admin-api/users").status_code == 403
    restored = admin.post("/auth/impersonation/stop")
    assert restored.status_code == 200, restored.text
    assert restored.json()["user"]["username"] == "admin"
    assert restored.json()["impersonation"] is None
    assert admin.get("/admin-api/users").status_code == 200
    audit = admin.get("/admin-api/audit").json()
    assert any(row["action"] == "session.impersonate" and row["targetId"] == target["id"] for row in audit)
    assert any(row["action"] == "session.impersonate.stop" and row["targetId"] == target["id"] for row in audit)


def test_user_write_scope_cannot_assign_roles_by_property_injection(admin):
    _, full = oauth(admin)
    person = scim_user(admin, full)
    _, limited = oauth(admin, ["users:write"])
    update = admin.patch(f'/api/v1/users/{person["id"]}', headers=limited, json={"roles": ["super-admin"]})
    assert update.status_code == 403, update.text
    create = admin.post("/api/v1/users", headers=limited, json={"username": unique(), "roles": ["super-admin"]})
    assert create.status_code == 403, create.text
    current = admin.get(f'/api/v1/users/{person["id"]}', headers=full).json()
    assert "super-admin" not in current["roles"]


def test_scim_failed_patch_is_atomic(admin):
    _, headers = oauth(admin)
    person = scim_user(admin, headers)
    path = f'/scim/v2/Users/{person["id"]}'
    result = admin.patch(path, headers=headers, json={"schemas": [PATCH], "Operations": [{"op": "replace", "path": "displayName", "value": "Should roll back"}, {"op": "replace", "path": "id", "value": "illegal"}]})
    assert result.status_code == 400, result.text
    assert admin.get(path, headers=headers).json()["displayName"] == person["displayName"]


def test_maker_checker_and_duplicate_approval(admin):
    accounts = admin.get("/banking/accounts").json()
    before = {a["id"]: a["balance"] for a in accounts}
    payment = admin.post("/banking/payments", json={"fromAccountId": accounts[0]["id"], "toAccountId": accounts[1]["id"], "amount": "12.34", "reference": "Acceptance synthetic payment"})
    assert payment.status_code == 201, payment.text
    payment_record = payment.json()
    payment_id = payment_record["id"]
    assert admin.post(f"/banking/payments/{payment_id}/approve").status_code == 403
    checker = next(user for user in admin.get("/admin-api/users").json() if user["id"] == payment_record["assignedApproverId"])
    admin.cookies.clear()
    login = admin.post("/auth/login", json={"username": checker["username"], "password": "Lab-Demo-2026!"})
    assert login.status_code == 200, login.text
    admin.headers["X-CSRF-Token"] = login.json()["csrfToken"]
    assert admin.post(f"/banking/payments/{payment_id}/approve").status_code == 200
    assert admin.post(f"/banking/payments/{payment_id}/approve").status_code == 409
    from decimal import Decimal
    after = {a["id"]: a["balance"] for a in admin.get("/banking/accounts").json()}
    assert Decimal(after[accounts[0]["id"]]) == Decimal(before[accounts[0]["id"]]) - Decimal("12.34")
    assert Decimal(after[accounts[1]["id"]]) == Decimal(before[accounts[1]["id"]]) + Decimal("12.34")


def test_client_attribute_policy_filters_reads_and_rejects_writes(admin):
    created = admin.post("/admin-api/clients", json={
        "name": unique("attribute-policy"),
        "scopes": ["users:read", "users:write"],
        "readAttributes": ["username", "email"],
        "writeAttributes": ["displayName"],
    })
    assert created.status_code == 201, created.text
    client = created.json()
    token = admin.post("/oauth/token", data={
        "grant_type": "client_credentials", "client_id": client["clientId"],
        "client_secret": client["clientSecret"], "scope": "users:read users:write",
    })
    headers = {"Authorization": "Bearer " + token.json()["access_token"]}
    users = admin.get("/api/v1/users", headers=headers).json()
    assert users and set(users[0]).issubset({"id", "username", "email"})
    target = users[0]["id"]
    assert admin.patch(f"/api/v1/users/{target}", headers=headers, json={"department": "Denied"}).status_code == 403
    allowed = admin.patch(f"/api/v1/users/{target}", headers=headers, json={"displayName": "Policy Allowed"})
    assert allowed.status_code == 200, allowed.text
    assert "displayName" not in allowed.json()


def test_custom_access_catalog_and_dashboard_chart_feeds(admin):
    permission_id = "TEST_" + uuid.uuid4().hex[:10].upper()
    permission = admin.post("/admin-api/permissions", json={"id": permission_id, "name": "Acceptance permission"})
    assert permission.status_code == 201, permission.text
    role = admin.post("/admin-api/roles", json={"name": unique("Custom role"), "permissions": [permission_id]})
    assert role.status_code == 201, role.text
    group = admin.post("/admin-api/groups", json={"displayName": unique("Custom group"), "roles": [role.json()["id"]], "members": []})
    assert group.status_code == 201, group.text
    assert admin.patch(f'/admin-api/groups/{group.json()["id"]}', json={"displayName": "Updated acceptance group"}).status_code == 200
    dashboard = admin.get("/admin-api/dashboard")
    assert dashboard.status_code == 200, dashboard.text
    charts = dashboard.json()["charts"]
    assert {"timeline", "protocols", "calendar", "countries", "departments", "userHealth", "sessions", "risk"}.issubset(charts)
    assert len(charts["timeline"]) == 12 and len(charts["calendar"]) == 21


def test_sso_provider_configuration_is_secret_safe(admin):
    created = admin.post("/admin-api/sso-providers", json={
        "name": "Acceptance Entra", "type": "oidc", "preset": "entra",
        "issuer": "https://login.microsoftonline.com/example/v2.0",
        "authorizationEndpoint": "https://login.microsoftonline.com/example/oauth2/v2.0/authorize",
        "tokenEndpoint": "https://login.microsoftonline.com/example/oauth2/v2.0/token",
        "jwksUri": "https://login.microsoftonline.com/example/discovery/v2.0/keys",
        "clientId": "acceptance-client", "clientSecret": "never-return-this",
        "enabled": True, "jitProvisioning": True, "defaultRoles": ["viewer"],
    })
    assert created.status_code == 201, created.text
    provider = created.json()
    assert "clientSecret" not in provider and "clientSecretEncrypted" not in provider
    public = admin.get("/sso/providers").json()
    assert any(item["id"] == provider["id"] for item in public)
    listed = admin.get("/admin-api/sso-providers").text
    assert "never-return-this" not in listed and "clientSecretEncrypted" not in listed
    assert admin.delete(f'/admin-api/sso-providers/{provider["id"]}').status_code == 204


def test_soap12_and_version_switch(admin):
    _, headers = oauth(admin)
    content = soap("ListUsers", version="1.2")
    try:
        assert admin.patch("/admin-api/protocols/soap11", json={"enabled": False}).status_code == 200
        reply = admin.post("/soap", headers={**headers, "Content-Type": "application/soap+xml"}, content=content)
        assert reply.status_code == 200, reply.text
        assert ET.fromstring(reply.text).tag == "{http://www.w3.org/2003/05/soap-envelope}Envelope"
        denied = admin.post("/soap", headers={**headers, "Content-Type": "text/xml"}, content=soap("ListUsers"))
        assert denied.status_code == 503
    finally:
        admin.patch("/admin-api/protocols/soap11", json={"enabled": True})


def test_expired_token_rejected_without_waiting(admin):
    registered, headers = oauth(admin)
    from main import Session, rows, save
    with Session.begin() as db:
        for token in rows(db, "token"):
            if token["clientId"] == registered["id"]:
                token["expiresAt"] = 0
                save(db, "token", token)
    assert admin.get("/api/v1/users", headers=headers).status_code == 401


def test_read_only_employee_cannot_reach_admin_or_mutate_identities(admin):
    employee = admin.post("/admin-api/users", json={"username": unique("viewer"), "password": "Viewer-Test-2026!", "roles": ["viewer"]})
    assert employee.status_code == 201, employee.text
    admin.cookies.clear()
    login = admin.post("/auth/login", json={"username": employee.json()["username"], "password": "Viewer-Test-2026!"})
    admin.headers["X-CSRF-Token"] = login.json()["csrfToken"]
    assert admin.get("/admin-api/clients").status_code == 403
    assert admin.get("/admin-api/audit").status_code == 403
    assert admin.patch(f'/api/v1/users/{employee.json()["id"]}', json={"roles": ["super-admin"]}).status_code == 403
    assert admin.get("/banking/customers").status_code == 200


def test_scim11_odata_jsonrpc_and_csv_share_canonical_state(admin):
    _, headers = oauth(admin)
    name = unique("adapter")
    legacy = admin.post("/scim/v1/Users", headers=headers, json={
        "schemas": ["urn:scim:schemas:core:1.0"], "userName": name,
        "displayName": "Legacy Adapter User", "active": True,
        "password": "Adapter-Test-2026!", "department": "Integration",
    })
    assert legacy.status_code == 201, legacy.text
    user_id = legacy.json()["id"]
    odata = admin.get(f"/odata/v4/Users({user_id})?$select=id,username,department", headers=headers)
    assert odata.status_code == 200 and odata.json()["username"] == name
    assert admin.get("/odata/v4/$metadata", headers=headers).text.startswith("<?xml")
    rpc = admin.post("/jsonrpc", headers=headers, json={"jsonrpc": "2.0", "id": 1, "method": "users.get", "params": {"id": user_id}})
    assert rpc.status_code == 200 and rpc.json()["result"]["id"] == user_id
    exported = admin.get("/api/v1/csv/users", headers=headers)
    assert exported.status_code == 200 and name in exported.text
    csv_name = unique("csv")
    imported = admin.post("/api/v1/csv/users", headers={**headers, "Content-Type": "text/csv"}, content=f"username,displayName,active\n{csv_name},CSV User,true\n")
    assert imported.status_code == 201, imported.text
    assert imported.json()["created"] == 1
    assert admin.get(f"/api/v1/users/{imported.json()['users'][0]['id']}", headers=headers).json()["username"] == csv_name


def test_native_grpc_identity_service(admin):
    _, headers = oauth(admin)
    channel = grpc.insecure_channel("127.0.0.1:50051")
    call = channel.unary_unary(
        "/identitylab.v1.IdentityService/ListUsers",
        request_serializer=Struct.SerializeToString,
        response_deserializer=Struct.FromString,
    )
    response = call(Struct(), metadata=(("authorization", headers["Authorization"]),), timeout=5)
    data = MessageToDict(response, preserving_proto_field_name=True)
    assert len(data["users"]) >= 15
    channel.close()


def test_signed_webhook_delivery_and_sftp_configuration(admin, monkeypatch):
    received = {}
    class Receiver(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            received.update(body=body, signature=self.headers.get("X-Identity-Signature"), event=self.headers.get("X-Identity-Event"))
            self.send_response(204); self.end_headers()
        def log_message(self, *args): pass
    server = HTTPServer(("127.0.0.1", 0), Receiver)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    monkeypatch.setenv("ALLOW_INSECURE_SSO", "true"); monkeypatch.setenv("ALLOW_PRIVATE_SSO", "true")
    hook = admin.post("/admin-api/webhooks", json={"name": "Acceptance receiver", "url": f"http://127.0.0.1:{server.server_port}/events", "events": ["user.updated"]})
    assert hook.status_code == 201, hook.text
    secret = hook.json()["secret"]
    delivery = admin.post(f"/admin-api/webhooks/{hook.json()['id']}/test")
    server.shutdown(); thread.join(timeout=2)
    assert delivery.status_code == 200 and delivery.json()["delivered"] is True
    expected = "sha256=" + hmac.new(secret.encode(), received["body"], hashlib.sha256).hexdigest()
    assert hmac.compare_digest(expected, received["signature"]) and received["event"] == "user.updated"
    assert admin.delete(f"/admin-api/webhooks/{hook.json()['id']}").status_code == 204
    blocked = admin.post("/admin-api/sftp-connectors", json={"name": "Private SFTP", "host": "127.0.0.1", "username": "lab", "password": "secret", "knownHostKey": "ssh-ed25519 AAAA", "remotePath": "/users.csv"})
    assert blocked.status_code == 400
