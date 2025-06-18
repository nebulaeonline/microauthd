# microauthd

microauthd is a self-hosted, embedded-friendly identity provider designed for internal services, machine-to-machine workflows, and constrained environments. It is written in C# using the .NET 8 SDK. It is **not** a replacement for Keycloak, Auth0, or Dex. It's a small, hardened component that forms one pillar of a larger authentication and authorization architecture.

Curent AOT status is: building & executing - 26MB executable, 35MB commit memory at rest, sub-50ms cold start time for both servers (slightly longer when enabling SSL), runs on Windows, Linux, and MacOS.

AOT build:

```bash

$ dotnet publish -r linux-x64 -c Release

or

C:\microauthd> dotnet publish -r win-x64 -c Release

```

microauthd uses a dual-port architecture with separate admin and auth endpoints, including separate signing keys for admin and auth tokens and completely separate API surfaces.

---

## microauthd Status Updates

2025-06-17

CRUD operations are now implemented for our 5 main data types: users, roles, permissions, clients, and scopes. The API is now consistent across all endpoints, with uniform response structures and error handling. The `mad` CLI tool has also been significantly improved to support these operations.

The python test harness is now complete and has been used to validate the API surface, the back-end functions and the `mad` CLI tool. `mad` can now be used to create, update, delete, and assign users, roles, permissions, clients, and scopes. Additional tests will be added for token grant, revocation and refresh token redemption (all 3 have been tested manually and via script and the system does work as intended).

2025-06-16

microauthd is currently not yet ready for production use. It has a LOT of rough edges right now. The code is functional and has been tested in a few scenarios, but it is most definitely not ready for production use. There is no documentation yet, either.

Please read on to understand its current capabilities, design philosophy, real-world security posture, known limitations, and how it will evolve toward a production-ready release.

Understand that this is **NOT A PRODUCTION READY SYSTEM**. It is not even suitable for testing in production-like environments yet. It is a work in progress.

---

## Design Goals / Philosophy

- **Be a Component, not a Platform**: microauthd isn't trying to manage your entire auth strategy. It's built to handle **identity**, **token issuance**, and **role/scope enforcement** leaving broader policy and SSO integration to other layers.
- **Zero Dependencies**: No Redis, no PostgreSQL, no external key services. SQLite is the only runtime requirement.
- **AOT Compatibility**: microauthd is written in C# using the .NET 8 SDK, and has been architected from day one to be AOT-compatible. Our philosophy is that cold start time, memory footprint, and binary size matter.
- **Secure by Default**: All sensitive operations are opt-in. No usernames in logs, no introspection leaks, no open scope writes.

## Security Posture

microauthd is architected for *deliberate minimal surface area*. Security features include:

- **Argon2id** password hashing with configurable time/memory/parallelism parameters
- **Per-session JWTs** (with unique jti) and optional **refresh tokens**
- **RSA or ECDSA Signing** with separate signing keys for auth and admin tokens
- **One-time-use Refresh Tokens** with hashed storage (`Argon2id` + SHA-256)
- **Audit Logging** of all sensitive operations (create, delete, assign, revoke, etc.)
- **Role + Scope Enforcement** via access tokens and scoped APIs
- Built-in support for **SQLCipher** (encrypted SQLite databases)

We have adoped a **Secure by Default** mindset. From its first line to its latest addition, microauthd has adopted this mindset as its #1 design philosophy- it's a core principle, not an afterthought. Many systems *claim* this, but microauthd demonstrates it in practice across multiple layers:

1. No Information Leaks by Design
    - Auth endpoints never reveal whether a user exists
      - Failed login attempts always return generic `403 Forbidden` with no detail
      - Reset/deactivation/lookups require full-scoped tokens- anonymous or mis-scoped requests get the same 403.
    - Unauthenticated endpoints (`/token`, `/oidc/token`) respond uniformly on failure
      - There's no way to distinguish "bad user" vs "bad password" vs "inactive user"
      - This is deliberate- and *correct*
    - *Result*: Attackers cannot probe usernames, emails, or scope capabilities via API behavior.
2. Token Security is Tight
    - JTI (unique token id) is generated per token and tracked in the database
    - Refresh tokens are one-time use, stored only as:
      - An Argon2id hash (`refresh_token_hash`)
      - A SHA-256 fingerprint (`refresh_token_sha256`) for lookup
    - All session records include client ID, `issued_at`, `expires_at`, and `token_use`- giving you replay analysis opportunities
    - *Result*: Even if a refresh token is leaked, it cannot be reused. Access tokens are short-lived and auditable.
3. Password Handling is Serious
    - All passwords and secrets use Argon2id, not bcrypt or PBKDF2, and with tunable time/mem/parallelism cost
    - Salt is cryptographically secure, randomly generated per password hashed
    - Passwords are not stored in plaintext or recoverable form
    - Failure counters and lockout timers are built in to resist brute force
    - *Result*: Even in constrained deployments, password security is best-in-class
4. Audit Logging Captures Everything
    - All privileged actions log:
      - `user_id` (if available)
      - `action` performed
      - `target` entity (e.g. `user:abc`, `role:def`)
      - `ip_address` and `user_agent`
    - Audit logs are stored in an append-only model and can be purged with retention policies
    - *Result*: There is a durable, inspectable trail for every sensitive operation
5. Minimal Attack Surface
    - No browser-exposed UI. microauthd exposes only a clean JSON/HTTP interface
    - Admin and Auth endpoints are split, run on different ports, and have separate JWT signing keys
    - Only a few admin scopes exist, and all are seeded securely in the database (`is_protected = 1`)
    - No scope or role creation is allowed via anonymous requests
    - *Result*: This isn't just a low surface, it's a well-armored one.
6. Defensive Defaults Everywhere
    - Routes default to `.RequireAuthorization()` unless explicitly meant to be public (e.g. `/ping`, `/jwks.json`)
    - Role Assignment, token issuance, and user creation all *fail safely* (no partial writes, no blind inserts)
    - The `OOBE` process **auto-assigns** the `MadAdmin` role via GUID only- names are flexible, but identity is not.
    - *Result*: You cannot shoot yourself in the foot unless you explicity try.

### Security Summary

Most systems *aspire* to be "secure by default." microauthd is **secure unless you go out of your way to make it insecure**- and even then, it tries to warn you.

If you're building internal tooling, embedded platforms, or machine-to-machine APIs, you won't find many identity providers with fewer seams, better defaults, or more consistent discipline.

## Cli Tool (mad)

microauthd ships with a full-featured CLI tool called `mad` that:

- Works with any admin endpoint (via Bearer token or session login)
- Allows automation of:
  - User creation, update, deletion, activation, and deactivation
  - Role creation, update, deletion, and assignment 
  - Permission checks
  - Scope + client management
- Uses a persistent token store (`~/.mad_token`) for login sessions
- Designed to be scriptable for CI/CD, provisioning, and test automation

Example usage:

```bash

mad session login --admin-url http://localhost:9041
mad user create --username alice --user-email alice@example.com --user-password s3cret --admin-url http://localhost:9041
mad role assign --user-id <user-guid> --role-id <role-guid> --admin-url http://localhost:9041

```

## Intended Ecosystem Role

microauthd is **not** a complete access platform. It is meant to:

- Act as a **lightweight identity provider** for internal services
- Serve **client_credentials OIDC tokens** to service accounts
- Plug into reverse proxies, gateways, or app servers for **JWT verification**
- Run **embedded in appliances or edge systems** with minimal setup
- Provide **authenticated backend control panels** via `mad` or custom tooling

Future bindings will be released for common languages (C#, Go, Python, Rust, JavaScript) to simplify integration.

---

## Current Status

### What Works
- Full user/session/refresh token lifecycle
- Role/Permission management with scoped APIs
- OIDC-compatible token issuance (`/token`, `/oidc/token`, `/jwks.json`)
- Admin vs Auth API separation (dual-port, dual-key architecture)
- CLI (`mad`) with full administrative control
- One-time-use refresh tokens with revocation
- Audit logging of nearly all privileged operations
- OOBE wizard that configures the full system and initial admin user
- AOT-safe JSON serialization across all DTOs

### What Still Needs Work

- `mad` CLI still a WIP but has improved significantly
- ~~Some minor inconsistencies in API response formatting~~ (APIs are now consistent)
- Token usage metadata is stored but not yet used for token tracing
- Audit log field consistency still being refined
- Swaggger/OpenAPI coverage is in progress (tags are set but needs polish)

### Known Shortcomings

- ~~**Update Endpoints are not yet implemented**~~ - updates are now implemented for users, roles, permissions, clients, and scopes
- **No multi-tenancy** support (by design)
- **No UI** - this is a text-first, CLI- and API-driven system
- **One shared DB connection** limits concurrency- will be addressed via per-request pooled connections
- **Does not enforce fine-graned resource ownership or external ACLs** - leaves this to calling systems
- OOBE is helpful, but **not quite production-ready** for large deployments (much better in v2 of OOBE now)
- OTP-based loginis not yet implemented (on roadmap)
- **Bindings for other languages are not yet published**

### Project Roadmap

1. ~~Add token introspection endpoint (`/introspect`)~~ Done.
2. ~~Implement replay detection for access tokens~~ Done.
3. Replace shared DB connection with per-request pooling (WAL-mode safe)
4. ~~Clean up API DTOs (uniform `MessageResponse`, consistent `id + name`)~~ Done.
5. ~~Launch test harness using `mad` + Python bindings (in progress)~~ Done.
6. Ship bindings for C#, Go, Python, Rust, and JavaScript (TS, Axios, Node)
7. More robust failed password mechanisms (~~rate limiting~~ (done) / exponential backoff)
8. OTP login flow
---

## Summary

microauthd hopes to get to an alpha-level release in the next few months as a small, secure, and deterministic identity service ideal for embedded control planes, internal APIs, or constrained deployments where full platforms are overkill.

It's not ready for general use today, but we're working diligently to get to an alpha release. The CLI is already (mostly) usable for local testing and automation, and the API surface is stable and predictable.

If you're building a system that needs to embed authentication but doesn't want the overhead or complexity of a Keycloak or Auth0, microauthd may be exactly what you're looking for and it's only getting better from here.
