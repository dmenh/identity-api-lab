# API contract and examples

Base URL: `http://localhost:8787`. Native gRPC uses `localhost:50051`. The runtime OpenAPI document at `/openapi.json`, WSDL at `/soap?wsdl`, protobuf file at `backend/identity.proto`, GraphQL schema and SCIM/OData discovery responses are authoritative.

The examples use environment variables so credentials do not enter shell history repeatedly:

```sh
export LAB_URL=http://localhost:8787
export CLIENT_ID='replace-me'
export CLIENT_SECRET='replace-me'
```

## Obtain and revoke an OAuth token

```sh
curl -sS -X POST "$LAB_URL/oauth/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=client_credentials' \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "client_secret=$CLIENT_SECRET" \
  --data-urlencode 'scope=users:read users:write roles:read'
```

Set the returned token as `ACCESS_TOKEN`, then revoke it when finished:

```sh
curl -sS -X POST "$LAB_URL/oauth/revoke" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "token=$ACCESS_TOKEN" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "client_secret=$CLIENT_SECRET"
```

Supported scopes are `users:read`, `users:write`, `roles:read`, `roles:write`, `groups:read`, `groups:write`, `banking:read` and `banking:write`. A client can request only registered scopes and use only registered protocol adapters.

## Authentication methods

The integration routes accept the following registered methods:

```sh
# OAuth bearer or authorization-code bearer
curl -H "Authorization: Bearer $ACCESS_TOKEN" "$LAB_URL/api/v1/users"

# API key
curl -H "X-API-Key: $API_KEY" "$LAB_URL/api/v1/users"

# HTTP Basic
curl -u "$CLIENT_ID:$CLIENT_SECRET" "$LAB_URL/api/v1/users"

# HTTP Digest
curl --digest -u "$CLIENT_ID:$CLIENT_SECRET" "$LAB_URL/api/v1/users"
```

JWT bearer tokens are issued by `POST /oauth/jwt`. HMAC requests use `X-Client-Id`, `X-Timestamp`, `X-Nonce`, `X-Content-SHA256` and `X-Signature`; the signature covers method, path, timestamp, nonce and body hash. The in-product documentation builds the exact canonical string. Browser-cookie mutations use `X-CSRF-Token` from `/auth/login`.

## REST

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" "$LAB_URL/api/v1/users"

curl -X POST "$LAB_URL/api/v1/users" \
  -H "Authorization: Bearer $ACCESS_TOKEN" -H 'Content-Type: application/json' \
  -d '{"username":"sam.lee","displayName":"Sam Lee","email":"sam.lee@example.test","department":"Technology","jobTitle":"Engineer","country":"Singapore","city":"Singapore","active":true,"password":"Temporary-2026!"}'

curl -X PATCH "$LAB_URL/api/v1/users/USER_ID" \
  -H "Authorization: Bearer $ACCESS_TOKEN" -H 'Content-Type: application/json' \
  -d '{"displayName":"Sam K. Lee"}'

curl -X PUT "$LAB_URL/api/v1/users/USER_ID/roles" \
  -H "Authorization: Bearer $ACCESS_TOKEN" -H 'Content-Type: application/json' \
  -d '{"roles":["viewer"]}'

curl -H "Authorization: Bearer $ACCESS_TOKEN" "$LAB_URL/api/v1/users/USER_ID/permissions"
curl -X DELETE -H "Authorization: Bearer $ACCESS_TOKEN" "$LAB_URL/api/v1/users/USER_ID"
```

## SCIM 2.0

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" "$LAB_URL/scim/v2/ServiceProviderConfig"
curl -H "Authorization: Bearer $ACCESS_TOKEN" "$LAB_URL/scim/v2/Users?filter=userName%20eq%20%22sam.lee%22"

curl -X POST "$LAB_URL/scim/v2/Users" \
  -H "Authorization: Bearer $ACCESS_TOKEN" -H 'Content-Type: application/scim+json' \
  -d '{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"sam.scim2","displayName":"Sam SCIM 2","active":true,"emails":[{"value":"sam.scim2@example.test","primary":true}],"password":"Temporary-2026!"}'

curl -X PATCH "$LAB_URL/scim/v2/Users/USER_ID" \
  -H "Authorization: Bearer $ACCESS_TOKEN" -H 'Content-Type: application/scim+json' \
  -d '{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}'
```

## SCIM 1.1

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" "$LAB_URL/scim/v1/Users?count=10"

curl -X POST "$LAB_URL/scim/v1/Users" \
  -H "Authorization: Bearer $ACCESS_TOKEN" -H 'Content-Type: application/json' \
  -d '{"schemas":["urn:scim:schemas:core:1.0"],"userName":"sam.scim1","displayName":"Sam SCIM 1","active":true,"emails":[{"value":"sam.scim1@example.test","primary":true}],"password":"Temporary-2026!"}'

curl -X PATCH "$LAB_URL/scim/v1/Users/USER_ID" \
  -H "Authorization: Bearer $ACCESS_TOKEN" -H 'Content-Type: application/json' \
  -d '{"active":false}'
```

## SOAP 1.1 and 1.2

```sh
curl "$LAB_URL/soap?wsdl"

curl -X POST "$LAB_URL/soap" \
  -H "Authorization: Bearer $ACCESS_TOKEN" -H 'Content-Type: text/xml; charset=utf-8' \
  -H 'SOAPAction: urn:identity-api-lab/ListUsers' \
  --data-binary '<?xml version="1.0"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:lab="urn:identity-api-lab"><soapenv:Body><lab:ListUsers/></soapenv:Body></soapenv:Envelope>'

curl -X POST "$LAB_URL/soap" \
  -H "Authorization: Bearer $ACCESS_TOKEN" -H 'Content-Type: application/soap+xml; charset=utf-8; action="urn:identity-api-lab/DisableUser"' \
  --data-binary '<?xml version="1.0"?><env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope" xmlns:lab="urn:identity-api-lab"><env:Body><lab:DisableUser><lab:userId>USER_ID</lab:userId></lab:DisableUser></env:Body></env:Envelope>'
```

Operations are `GetUser`, `ListUsers`, `CreateUser`, `UpdateUser`, `DisableUser`, `EnableUser` and `DeleteUser`.

## GraphQL

```sh
curl -X POST "$LAB_URL/graphql" \
  -H "Authorization: Bearer $ACCESS_TOKEN" -H 'Content-Type: application/json' \
  -d '{"query":"query($id: ID!){ user(id:$id){ id username active roles permissions } effectivePermissions(userId:$id) }","variables":{"id":"USER_ID"}}'

curl -X POST "$LAB_URL/graphql" \
  -H "Authorization: Bearer $ACCESS_TOKEN" -H 'Content-Type: application/json' \
  -d '{"query":"mutation($id:ID!){ setUserActive(id:$id,active:false){ id username active } }","variables":{"id":"USER_ID"}}'
```

## OData 4.0

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" "$LAB_URL/odata/v4/\$metadata"
curl -H "Authorization: Bearer $ACCESS_TOKEN" "$LAB_URL/odata/v4/Users?\$select=id,username,email&\$filter=active%20eq%20true&\$top=10&\$count=true"

curl -X POST "$LAB_URL/odata/v4/Users" \
  -H "Authorization: Bearer $ACCESS_TOKEN" -H 'Content-Type: application/json' \
  -d '{"username":"sam.odata","displayName":"Sam OData","email":"sam.odata@example.test","active":true,"password":"Temporary-2026!"}'

curl -X PATCH "$LAB_URL/odata/v4/Users(USER_ID)" \
  -H "Authorization: Bearer $ACCESS_TOKEN" -H 'Content-Type: application/json' \
  -d '{"displayName":"Sam OData Updated"}'
```

## JSON-RPC 2.0

```sh
curl -X POST "$LAB_URL/jsonrpc" \
  -H "Authorization: Bearer $ACCESS_TOKEN" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"users.list","params":{"count":10}}'

curl -X POST "$LAB_URL/jsonrpc" \
  -H "Authorization: Bearer $ACCESS_TOKEN" -H 'Content-Type: application/json' \
  -d '[{"jsonrpc":"2.0","id":1,"method":"users.get","params":{"id":"USER_ID"}},{"jsonrpc":"2.0","id":2,"method":"users.disable","params":{"id":"USER_ID"}}]'
```

Methods are `users.list`, `users.get`, `users.create`, `users.update` and `users.disable`. Batches are limited to 20 calls.

## Native gRPC

```sh
grpcurl -plaintext -import-path backend -proto identity.proto \
  -H "authorization: Bearer $ACCESS_TOKEN" -d '{}' \
  localhost:50051 identitylab.v1.IdentityService/ListUsers

grpcurl -plaintext -import-path backend -proto identity.proto \
  -H "authorization: Bearer $ACCESS_TOKEN" -d '{"id":"USER_ID"}' \
  localhost:50051 identitylab.v1.IdentityService/GetUser
```

The service methods are `ListUsers`, `GetUser`, `CreateUser`, `UpdateUser` and `DisableUser`. Public gRPC requires a platform TCP endpoint and TLS termination.

## CSV

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" "$LAB_URL/api/v1/csv/users" -o users.csv

curl -X POST "$LAB_URL/api/v1/csv/users" \
  -H "Authorization: Bearer $ACCESS_TOKEN" -H 'Content-Type: text/csv' \
  --data-binary @users.csv
```

Imports are limited to 500 rows and a 1 MiB request body. Headers outside the supported identity profile are rejected.

## Webhooks

Webhook administration uses an authenticated administrator browser session and CSRF token:

```sh
curl -b cookies.txt -X POST "$LAB_URL/admin-api/webhooks" \
  -H "X-CSRF-Token: $CSRF_TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"Identity lifecycle","url":"https://receiver.example.test/identity","events":["user.created","user.updated","user.disabled","user.deleted"],"secret":"replace-with-a-long-random-secret","enabled":true}'

curl -b cookies.txt -X POST "$LAB_URL/admin-api/webhooks/WEBHOOK_ID/test" -H "X-CSRF-Token: $CSRF_TOKEN"
curl -b cookies.txt "$LAB_URL/admin-api/webhook-deliveries"
```

Receivers verify `X-IdentityLab-Signature` over the raw body with the subscription secret and use event/delivery/timestamp headers for routing and replay control.

## SFTP CSV connectors

```sh
curl -b cookies.txt -X POST "$LAB_URL/admin-api/sftp-connectors" \
  -H "X-CSRF-Token: $CSRF_TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"Daily identity exchange","host":"sftp.example.test","port":22,"username":"identitylab","password":"replace-me","remotePath":"imports/users.csv","hostKey":"ssh-ed25519 AAAA...","enabled":true}'

curl -b cookies.txt -X POST "$LAB_URL/admin-api/sftp-connectors/CONNECTOR_ID/test" -H "X-CSRF-Token: $CSRF_TOKEN"
curl -b cookies.txt -X POST "$LAB_URL/admin-api/sftp-connectors/CONNECTOR_ID/push" -H "X-CSRF-Token: $CSRF_TOKEN"
curl -b cookies.txt -X POST "$LAB_URL/admin-api/sftp-connectors/CONNECTOR_ID/pull" -H "X-CSRF-Token: $CSRF_TOKEN"
```

## Banking simulator

```sh
curl -b cookies.txt "$LAB_URL/banking/dashboard"
curl -b cookies.txt "$LAB_URL/banking/accounts"

curl -b cookies.txt -X POST "$LAB_URL/banking/payments" \
  -H "X-CSRF-Token: $CSRF_TOKEN" -H 'Content-Type: application/json' \
  -d '{"fromAccountId":"ACCOUNT_ID","toAccountId":"ACCOUNT_ID","amount":"125.00","reference":"Invoice 1042"}'

curl -b cookies.txt -X POST "$LAB_URL/banking/payments/PAYMENT_ID/approve" -H "X-CSRF-Token: $CSRF_TOKEN"
curl -b cookies.txt -X POST "$LAB_URL/banking/payments/PAYMENT_ID/reject" -H "X-CSRF-Token: $CSRF_TOKEN" -H 'Content-Type: application/json' -d '{"reason":"Supporting document required"}'
```

Payments are synthetic. Approval verifies permission, assigned approver, maker/checker separation, account state and available balance, then records the transaction and audit evidence atomically.
