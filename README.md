# microauthd

microauthd is a self-hosted, embedded-friendly identity provider designed for internal services, machine-to-machine workflows, and constrained environments. It is written in C# using the .NET 8 SDK. It is **not** a replacement for Keycloak, Auth0, or Dex. It's a small, hardened component that forms one pillar of a larger authentication and authorization architecture.

microauthd uses a dual-port architecture with separate admin and auth endpoints, including separate signing keys for admin and auth tokens and completely separate API surfaces.

**A Note on Standards**

microauthd is a lightweight, security-first OAuth 2.0 authorization server with OpenID Connect support. It supports standard flows such as password, client_credentials, refresh_token, and PKCE, and includes ID token issuance and discovery endpoints for OIDC compatibility. It is suitable for integrating with OIDC clients, SDKs, and libraries that conform to the OpenID Connect specification.

microauthd is not a Certified OpenID Connect Provider, nor is it Fully OIDC Compliant as it has not been validated against the OIDC conformance suite, although adherence to one or more OIDC profiles is planned prior to a v1.0, along with validation against the publicly available compliance test.

Currently, microauthd can not act as an OIDC client, but support is planned prior to the 1.0 release. microauthd currently supports the /userinfo, /authorize, /login, /token, /oidc/token, /introspect, /.well-known/openid-configuration, and /jwks.json endpoints, and can issue ID tokens alongside access tokens.

**What are the Various Visual Studio Projects?**

- `mad` is the CLI tool for managing microauthd. It allows you to create users, roles, permissions, and clients, as well as manage tokens and sessions.
- `madClient` is a client library for making ADMIN & AUTH API calls via the JSON/HTTP APIs.
- `madAuthClient` is a client library for integrating the token-based authentication of microauthd with ASP.NET Core's cookie authentication (including refresh token middleware).
- `madRazorExample` is a sample ASP.NET Core Razor Pages application that uses the `madAuthClient` library to authenticate users and manage roles/permissions.
- `madTypes` contains the data transfer objects (DTOs) used by `microauthd`, the `mad` CLI tool, the `madClient` library, and the additional bindings provided for other languages (these DTOs include common objects, requests & responses)
- `madOobe` is the out-of-the-box experience (OOBE) tool that sets up microauthd for the first time, including initial admin user creation and database initialization. The OOBE is also usable directly from `microauthd`, unless the "--docker" command line option is specified, due to the way Docker handles stdin/stdout.
- `microauthd` is the main project that contains the identity server implementation, including the ADMIN and AUTH endpoints, token issuance, user management, role management, and the web-based GUI.
- `madTests` is an Xunit test project that contains tests for microauthd's functionality. End-to-end tests are written in Python and use the `mad` CLI tool to interact with the JSON/HTTP ADMIN endpoints that microauthd exposes for managing the system.
- `docs` is not a Visual Studio project, but a directory that contains documentation for microauthd (getting stronger every day). It includes explanations of the architecture, addresses the concepts of Users, Permissions, and Scopes, contains code examples, details the TOTP flow, and talks about the OOBE and the various configuration options available.

**Recent Features Include:**

1.  Caching of the admin-url and the admin token in `mad` CLI tool for convenience.
2.  Support for PKCE (Proof Key for Code Exchange) in the authorization code flow.
3.  Implementation of ID Token issuance in compliance with OpenID Connect.
4.  Support for TOTP-based login with QR code generation and verification.
5.  Improved performance with client secret caching and password hash caching.
6.  Database schema versioning for easier upgrades.
7.  Support for serving static files (e.g., login page) from the `/public` folder for the AUTH server.
8.  A web-based management GUI using Razor Pages for managing users, roles, permissions, scopes, clients, sessions & refresh tokens.
9.  Aot-safe JSON serialization across all DTOs for better performance and reduced memory footprint.
10. Robust testing suite using Xunit for internal functions and end-to-end testing via Pytest and the `mad` CLI tool. Approximately 90% coverage for services, and around the same 90% for API coverage.

---

## microauthd Status Updates

Check out my blog post on [why microauthd](https://purplekungfu.com/Post/9/dont-roll-your-own-auth), my follow up [Auth Rolled: Part Deux](https://purplekungfu.com/Post/10/auth-rolled-part-deux) and my dev.to post on [microauthd](https://dev.to/nebulae/i-rolled-my-own-auth-p8o).

I will keep the last 5 days of updates here; older updates can be found in the [CHANGELOG](CHANGELOG.md) file.

**2025-06-30**

The testsuite is rounding into shape. Normally I would have been writing tests as I went, but this one is a bit trickier than most. We have the end-to-end testing via the Python suite, which hits the CRUD on every endpoint including token issuance, renewal and invalidation testing. But there's a lot of standalone and database functions that don't get e2e testing via Python, and so I'm filling in the blanks. It's about 30% of the way done. I hope to have close to 100% coverage within the next week or so, so you can rest assured that microauthd is being worked out from a testing perspective.

**2025-06-29**

The OOBE tool has been separated into a standalone project called `madOobe`. It will still run as part of microauthd, but is accessible as a standalone tool for those who need it (Docker users primarily). You can start microauthd with --docker to prevent the OOBE tool from running as part of the first run.

I am working on packaging this up for Windows, Linux, and MacOS. The Linux build will also include a Docker image that can optionally be used to run microauthd in a container.

**2025-06-28**

On the usability front, I just wanted to say I'm happy about finally versioning our database schema for migrations, and now no longer requiring `mad` users to enter --admin-url on the CLI. We are slowly getting to a usability point that I think can drive adoption of microauthd. Additionally, if you are experimenting with the package, we would like to hear from you. Pain points, missing features, whatever. As we seek to move to a true v1.0 release, it will be important to get feedback so we can get things in order. Don't be shy. Thanks!

If you don't feel comfortable reaching out via GitHub issues, you can always email me at nebulae at nebulae dot online.

**2025-06-27**

Today we introduced Id Token issuance in compliance with OpenID Connect. This allows microauthd to issue ID tokens alongside access tokens, providing a standardized way to convey user identity and authentication information. The ID token is a JWT that contains claims about the authenticated user, such as their unique identifier, email, and other profile information.

On performance, changing the hashing strategy for refresh tokens to use SHA-256 only instead of Argon2id and SHA-256 brought another 50% speedup, bringing us to around 60rps with bursts to 1500 rps.

We now cache password hashes (if enabled); the feature and duration are configurable via --enable-pass-cache and --pass-cache-duration (default is 5 minutes). We are now seeing throughput of over 600 rps, with burst at 3,000 rps. This means microauthd is now performing on par or better than its peers.

We have implemented db schema versioning, which will allow us to upgrade painlessly in the future. If you have started with a version prior to the last few days, you should be fine. Users on much older versions may have to do some surgery. Let us know if you need assistance.

Big change with `mad` CLI tool: it now uses a persistent admin url that is set the first time you run `mad session login`. For commands issued after that, you can omit the --admin-url cli option and it will just work. Thank goodness- that was my least favorite part of mad.

**2025-06-26**

So why is microauthd slow? Well, it is secure. The truth is that microauthd is cpu limited- it does a lot of argon2id hashing (and verifying) in the name of security; so depending upon your settings, you *will* notice it. Token issuance profiling shows 30%+ of microauthd's time is spent verifying the username & password, 30%+ of time is spent verifying the client id & client secret, and 30%+ of the time is spent generating the refresh token. What does this mean? Argon2id is deliberately expensive, and it means we're cpu bound, something async'ing all the things will not fix. It means that in the name of security, we are always going to be cpu bound. There's a few tracks we can take- we can verify the client secret by a different hash, we can cache the client secrets, and we can tone down the argon2id parameters (we run at 2 time cost / 2 parallelism / and 32MB memory). That would probably altogether result in a 40% speedup (not insignificant). But microauthd values security above all other things. So where is it falling now? ~20rps bursting to 1100rps. Not super fast. But is it suitable for 90% of the sites out there? Yes. So just keep that in mind when evaluating microauthd. I was getting < 1 rps on KeyCloak and Authentik, so we're at least in the ballpark. These benchmarks were run with 5,000 requests and 50 concurrent requests.

microauthd isn't built to be the fastest — it’s built to be **secure**, **transparent**, and **manageable**. If you're running an API with tens of millions of users, you may outgrow it. But for 99% of modern apps, it’s more than fast enough. So when you evaluate microauthd, keep this in mind: Security-first means CPU-first, and we wouldn’t have it any other way.

Adding client secret caching brought about a 50% speedup in token issuance, and now microauthd is hovering around 30rps with bursts to 1200rps. This is a significant improvement.

---

## Design Goals / Philosophy

- **Be a Component, not a Platform**: microauthd isn't trying to manage your entire auth strategy. It's built to handle **identity**, **token issuance**, and **role/scope enforcement** leaving broader policy and SSO integration to other layers.
- **Zero Dependencies**: No Redis, no PostgreSQL, no external key services. SQLite is the only runtime requirement.
- ~~**AOT Compatibility**: microauthd is written in C# using the .NET 8 SDK, and has been architected from day one to be AOT-compatible. Our philosophy is that cold start time, memory footprint, and binary size matter.~~ (the AOT experiment is over)
- **Secure by Default**: All sensitive operations are opt-in. No usernames in logs, no introspection leaks, no open scope writes.

## Security Posture

microauthd is architected for *deliberate minimal surface area*. Security features include:

- **Argon2id** password hashing with configurable time/memory/parallelism parameters
- **Per-session JWTs** (with unique jti) and optional **refresh tokens**
- **RSA or ECDSA Signing** with separate signing keys for auth and admin tokens
- **One-time-use Refresh Tokens** with hashed storage (SHA-256; refresh tokens themselves are never stored)
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
    - microauthd exposes a clean JSON/HTTP interface, as well as an ADMIN gui via Razor Pages- the two do not overlap: logging in to the admin interface does not grant the ability to call ADMIN or AUTH endpoints- all endpoints are bearer token only.
    - Admin and Auth endpoints are split, run on different ports, and have separate JWT signing keys
    - Only a few admin scopes exist, and all are seeded securely in the database (these scopes are flagged as protected and cannot be removed, though they can be renamed)
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

- Works with any admin endpoint (via Bearer token; which can be cached for convenience)
- Allows automation of:
  - User creation, update, deletion, activation, and deactivation
  - Role creation, update, deletion, and assignment 
  - Permission creation, update, deletion & checks
  - Full Scope + client management
- Uses a persistent token store (`~/.mad_token`) for login sessions; can cache the admin url as well for convenience
- Designed to be scriptable for CI/CD, provisioning, and test automation

Example usage:

```bash

mad session login --admin-url http://localhost:9041
mad user create --username alice --user-email alice@example.com --user-password s3cret
mad role assign --user-id <user-guid> --role-id <role-guid>

```

## Intended Ecosystem Role

microauthd is **not** a complete access platform. It is meant to:

- Act as a **lightweight identity provider** for internal services
- Serve **client_credentials OIDC tokens** to service accounts
- Plug into reverse proxies, gateways, or app servers for **JWT verification**
- Run **embedded in appliances or edge systems** with minimal setup
- Provide **authenticated backend control panels** via `mad` or custom tooling

Future bindings will be released for common languages (C#, ~~Go~~ (Done), ~~Python~~ (Done), Rust, ~~JavaScript~~ (Done)) to simplify integration.

---

## Current Status

### What Works
- Full user/session/refresh token lifecycle
- Role/Permission management with scoped APIs
- OIDC-compatible token issuance (`/token`, `/oidc/token`, `/jwks.json`)
- Admin vs Auth API separation (dual-port, dual-key architecture)
- CLI (`mad`) with full administrative control
- One-time-use refresh tokens with revocation
- Audit logging of all privileged operations
- OOBE wizard that configures the full system and initial admin user
- AOT-safe JSON serialization across all DTOs

### What Still Needs Work

- ~~Web-based management GUI is in progress (Razor Pages)~~ (Mostly complete)
- ~~`mad` CLI still a WIP but has improved significantly~~ (`mad` CLI has feature parity with the API)
- ~~Some minor inconsistencies in API response formatting~~ (APIs are now consistent)
- ~~Token usage metadata is stored but not yet used for token tracing~~ (Tokens should be traceable now)
- ~~Audit log field consistency still being refined~~ (Audit logs are now consistent)
- Swaggger/OpenAPI coverage is in progress (tags are set but needs polish)

### Known Shortcomings

- ~~**Update Endpoints are not yet implemented**~~ - updates are now implemented for users, roles, permissions, clients, and scopes
- **No multi-tenancy** support (by design)
- ~~**No UI** - this is a text-first, CLI- and API-driven system~~ (In progress)
- **One shared DB connection** limits concurrency- will be addressed via per-request pooled connections
- **Does not enforce fine-graned resource ownership or external ACLs** - leaves this to calling systems
- ~~OOBE is **not quite production-ready** for large deployments~~ (OOBE v2 is tight)
- ~~OTP-based loginis not yet implemented (on roadmap)~~ (Done)
- **Bindings for Python, Go, and JS/TS are in the repo; C# bindings have their own project; other languages are not yet published**

### Project Roadmap

1. ~~Add token introspection endpoint (`/introspect`)~~ Done.
2. ~~Implement replay detection for access tokens~~ Done.
3. Replace shared DB connection with per-request pooling (WAL-mode safe)
4. ~~Clean up API DTOs (uniform `MessageResponse`, consistent `id + name`)~~ Done.
5. ~~Launch test harness using `mad` + Python bindings (in progress)~~ Done.
6. Ship bindings for ~~C#~~ (Done) & Rust (forthcoming)
7. More robust failed password mechanisms (~~rate limiting~~ (done) / exponential backoff)
8. ~~OTP login flow~~ (Done)
9. Example code for common languages (slowly coming along for languages that have bindings)
10. Documentation for all endpoints, CLI, and bindings

---

## Summary

microauthd hopes to get to an alpha-level release in the next few months as a small, secure, and deterministic identity service ideal for embedded control planes, internal APIs, or constrained deployments where full platforms are overkill.

It's not ready for general use today, but we're working diligently to get to an alpha release. The CLI is already (mostly) usable for local testing and automation, and the API surface is stable and predictable.

If you're building a system that needs to embed authentication but doesn't want the overhead or complexity of a Keycloak or Auth0, microauthd may be exactly what you're looking for and it's only getting better from here.
