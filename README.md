# InsecureShop

InsecureShop is a deliberately vulnerable API security lab built with FastAPI, REST and GraphQL. It simulates a small online shop and provides vulnerable and secure implementations side by side so each issue can be exploited, understood and compared with a mitigation.

This project is intentionally insecure and must not be used as a production template.

## Tech Stack

- Python
- FastAPI
- Uvicorn
- SQLAlchemy
- SQLite
- Pydantic
- python-jose
- Passlib/bcrypt
- Strawberry GraphQL
- pytest
- httpx
- HTML, CSS and JavaScript

## Setup

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Main URLs:

- Web app: `http://localhost:8000`
- Swagger/OpenAPI: `http://localhost:8000/docs`
- Vulnerable GraphQL: `http://localhost:8000/graphql/vulnerable`
- Secure GraphQL: `http://localhost:8000/graphql/secure`
- GraphQL Lab: `http://localhost:8000/static/graphql-lab.html`

The SQLite database `insecure_api.db` is created automatically on first startup. To reset the initial data, stop the app, delete `insecure_api.db`, and start it again.

## Test Accounts

| Name | Email | Password | Role |
| --- | --- | --- | --- |
| André | `andre@example.com` | `password123` | `user` |
| Maria | `maria@example.com` | `password123` | `user` |
| Admin | `admin@example.com` | `admin123` | `admin` |

In the seed data, orders `1` and `2` belong to André, while orders `3` and `4` belong to Maria.

## Project Structure

```text
app/
  main.py                 # FastAPI entrypoint
  database.py             # SQLite/SQLAlchemy configuration
  models.py               # SQLAlchemy models
  schemas.py              # Pydantic request/response schemas
  security.py             # authentication, tokens and permission helpers
  seed.py                 # initial demo data
  services.py             # shared business logic
  graphql/
    vulnerable.py         # intentionally vulnerable GraphQL schema
    secure.py             # secure GraphQL schema for comparison
  routers/
    auth.py               # login endpoint used by the app
    vulnerable.py         # intentionally vulnerable REST endpoints
    secure.py             # secure REST endpoints for comparison
  static/
    login.html
    dashboard.html
    orders.html
    order-detail.html
    profile.html
    graphql-lab.html      # browser UI for GraphQL scenarios
    style.css
    app.js
```

The main frontend intentionally uses the vulnerable REST API so the impact is visible in a normal user flow. The secure REST and GraphQL endpoints exist for technical comparison and documentation.

## Vulnerability Summary

| Vulnerability | Vulnerable surface | Mitigation |
| --- | --- | --- |
| Excessive Data Exposure | `GET /api/vulnerable/me` | Return only required fields through a limited response schema. |
| BOLA / IDOR | `GET /api/vulnerable/orders/{order_id}` | Check object ownership before returning the order. |
| Mass Assignment | `PATCH /api/vulnerable/me` | Accept only explicitly allowed fields and reject extra properties. |
| Broken Function Level Authorization | `GET /api/vulnerable/admin/users` | Require admin permissions before running administrative functions. |
| Missing Rate Limiting | `POST /api/auth/login` | Limit failed login attempts per email/IP within a time window. |
| GraphQL Excessive Data Exposure | `POST /graphql/vulnerable` with `me { passwordHash internalNotes }` | Keep sensitive fields out of public GraphQL types. |
| GraphQL BOLA / IDOR | `POST /graphql/vulnerable` with `order(id: 3)` | Validate ownership inside the resolver. |
| GraphQL Mass Assignment | `POST /graphql/vulnerable` with `updateMe(input: {role, isAdmin})` | Use restricted input types with only safe fields. |
| GraphQL Broken Function Level Authorization | `POST /graphql/vulnerable` with `users` | Enforce admin checks inside the resolver. |
| GraphQL Introspection / Resource Abuse | `POST /graphql/vulnerable` | Disable introspection where appropriate and reduce recursive/costly schema paths. |

## Get an Access Token

```bash
curl -s -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"andre@example.com","password":"password123"}'
```

Save the returned token:

```bash
TOKEN="paste_access_token_here"
```

## REST API Walkthrough

### 1. Excessive Data Exposure

The vulnerable API returns internal and sensitive user fields.

```bash
curl http://localhost:8000/api/vulnerable/me \
  -H "Authorization: Bearer $TOKEN"
```

Expected result: the response includes fields such as `password_hash`, `role`, `is_admin`, `internal_notes` and `account_status`.

Secure comparison:

```bash
curl http://localhost:8000/api/secure/me \
  -H "Authorization: Bearer $TOKEN"
```

Expected result: only `id`, `name` and `email` are returned.

### 2. BOLA / IDOR

The vulnerable API authenticates the user but does not verify that the requested object belongs to that user.

```bash
curl http://localhost:8000/api/vulnerable/orders \
  -H "Authorization: Bearer $TOKEN"
```

André can then manually request Maria's order:

```bash
curl http://localhost:8000/api/vulnerable/orders/3 \
  -H "Authorization: Bearer $TOKEN"
```

Secure comparison:

```bash
curl -i http://localhost:8000/api/secure/orders/3 \
  -H "Authorization: Bearer $TOKEN"
```

Expected result: `403 Forbidden`.

### 3. Mass Assignment

The vulnerable endpoint accepts client-controlled fields without a strict allowlist.

```bash
curl -X PATCH http://localhost:8000/api/vulnerable/me \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"André","email":"andre@example.com","role":"admin","is_admin":true}'
```

Confirm the privilege change:

```bash
curl http://localhost:8000/api/vulnerable/me \
  -H "Authorization: Bearer $TOKEN"
```

Secure comparison:

```bash
curl -i -X PATCH http://localhost:8000/api/secure/me \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"André","email":"andre@example.com","role":"admin","is_admin":true}'
```

Expected result: `422 Unprocessable Entity` because extra fields are rejected.

### 4. Broken Function Level Authorization

The vulnerable admin endpoint only checks authentication, not authorization.

Log in as Maria:

```bash
curl -s -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"maria@example.com","password":"password123"}'
```

Save Maria's token:

```bash
TOKEN_MARIA="paste_maria_access_token_here"
```

A normal authenticated user can call the vulnerable admin route:

```bash
curl http://localhost:8000/api/vulnerable/admin/users \
  -H "Authorization: Bearer $TOKEN_MARIA"
```

Secure comparison:

```bash
curl -i http://localhost:8000/api/secure/admin/users \
  -H "Authorization: Bearer $TOKEN_MARIA"
```

Expected result: `403 Forbidden`.

### 5. Missing Rate Limiting

The frontend login endpoint does not limit failed authentication attempts.

```bash
curl -i -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"andre@example.com","password":"wrong"}'
```

Secure comparison:

```bash
for i in 1 2 3 4 5 6; do
  curl -i -X POST http://localhost:8000/api/secure/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"andre@example.com","password":"wrong"}'
done
```

Expected result: after 5 failed attempts per minute for the same email/IP, the secure endpoint returns `429 Too Many Requests`.

## GraphQL Lab

The project also exposes two GraphQL schemas:

- `/graphql/vulnerable`: GraphiQL and introspection enabled, permissive resolvers and sensitive fields exposed.
- `/graphql/secure`: GraphiQL disabled, introspection blocked, authorization checks and limited schema types.

The browser lab is available at:

```text
http://localhost:8000/static/graphql-lab.html
```

It reuses the token stored after login and provides ready-made scenarios for both vulnerable and secure GraphQL endpoints.

### GraphQL 1. Excessive Data Exposure

The vulnerable schema allows clients to request internal user fields.

```bash
curl -s http://localhost:8000/graphql/vulnerable \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"query { me { id email role isAdmin passwordHash internalNotes accountStatus } }"}'
```

Secure comparison:

```bash
curl -s http://localhost:8000/graphql/secure \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"query { me { id email passwordHash } }"}'
```

Expected result: the secure schema returns GraphQL `errors` because `passwordHash` is not part of `UserSafe`.

### GraphQL 2. BOLA / IDOR

The vulnerable resolver returns another user's order when the ID is manipulated.

```bash
curl -s http://localhost:8000/graphql/vulnerable \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"query { order(id: 3) { id product shippingAddress userId user { id email } } }"}'
```

Secure comparison:

```bash
curl -s http://localhost:8000/graphql/secure \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"query { order(id: 3) { id product shippingAddress userId } }"}'
```

Expected result: the secure resolver returns an error because the order belongs to another user.

### GraphQL 3. Broken Function Level Authorization

A normal user can list all users through the vulnerable schema.

```bash
curl -s http://localhost:8000/graphql/vulnerable \
  -H "Authorization: Bearer $TOKEN_MARIA" \
  -H "Content-Type: application/json" \
  -d '{"query":"query { users { id email role isAdmin passwordHash } }"}'
```

Secure comparison:

```bash
curl -s http://localhost:8000/graphql/secure \
  -H "Authorization: Bearer $TOKEN_MARIA" \
  -H "Content-Type: application/json" \
  -d '{"query":"query { adminUsers { id email role isAdmin } }"}'
```

Expected result: the secure resolver returns an admin-only authorization error.

### GraphQL 4. Mass Assignment

The vulnerable mutation accepts privileged fields.

```bash
curl -s http://localhost:8000/graphql/vulnerable \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation { updateMe(input: {role: \"admin\", isAdmin: true, internalNotes: \"Promoted through vulnerable GraphQL\"}) { id email role isAdmin internalNotes } }"}'
```

Secure comparison:

```bash
curl -s http://localhost:8000/graphql/secure \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation { updateMe(input: {role: \"admin\", isAdmin: true}) { id email } }"}'
```

Expected result: the secure schema rejects `role` and `isAdmin` because the safe input only accepts `name` and `email`.

After testing mass assignment, reset the database if you want the original state back:

```bash
rm insecure_api.db
uvicorn app.main:app --reload
```

### GraphQL 5. Recursive Queries and Introspection

The vulnerable schema allows recursive traversal between users and orders.

```bash
curl -s http://localhost:8000/graphql/vulnerable \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"query { me { orders { id user { id orders { id product } } } } }"}'
```

The secure schema does not expose a recursive `order -> user -> orders` path and blocks introspection:

```bash
curl -s http://localhost:8000/graphql/secure \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"query { __schema { queryType { name } } }"}'
```

Expected result: the secure endpoint returns GraphQL `errors`.

## Tests

```bash
pytest
```

The test suite covers the vulnerable and secure GraphQL scenarios using an isolated SQLite database configured through `INSECURESHOP_DATABASE_URL`.
