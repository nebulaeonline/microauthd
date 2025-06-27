# microauthd

microauthd is a self-hosted, embedded-friendly identity provider designed for internal services, machine-to-machine workflows, and constrained environments. It is written in C# using the .NET 8 SDK. It is **not** a replacement for Keycloak, Auth0, or Dex. It's a small, hardened component that forms one pillar of a larger authentication and authorization architecture.

microauthd uses a dual-port architecture with separate admin and auth endpoints, including separate signing keys for admin and auth tokens and completely separate API surfaces.

---

## microauthd Status Updates

Check out my blog post on [why microauthd](https://purplekungfu.com/Post/9/dont-roll-your-own-auth) and my dev.to post on [microauthd](https://dev.to/nebulae/i-rolled-my-own-auth-p8o).

**2025-06-26**

So why is microauthd slow? Well, it is secure. The truth is that microauthd is cpu limited- it does a lot of argon2id hashing (and verifying) in the name of security; so depending upon your settings, you *will* notice it. Token issuance profiling shows 30%+ of microauthd's time is spent verifying the username & password, 30%+ of time is spent verifying the client id & client secret, and 30%+ of the time is spent generating the refresh token. What does this mean? Argon2id is deliberately expense, and it means we're cpu bound, something async'ing all the things will not fix. It means that in the name of security, we are always going to be cpu bound. There's a few tracks we can take- we can verify the client secret by a different hash, we can cache the client secrets, and we can tone down the argon2id parameters (we run at 2 time cost / 2 parallelism / and 32MB memory). That would probably altogether result in a 40% speedup (not insignificant). But microauthd values security above all other things. So where is it falling now? ~20rps bursting to 1100rps. Not super fast. But is it suitable for 90% of the sites out there? Yes. So just keep that in mind when evaluating microauthd. I was getting < 1 rps on KeyCloak and Authentik, so we're at least in the ballpark. These benchmarks were run with 5,000 requests and 50 concurrent requests.

microauthd isn't built to be the fastest — it’s built to be **secure**, **transparent**, and **manageable**. If you're running an API with tens of millions of users, you may outgrow it. But for 99% of modern apps, it’s more than fast enough. So when you evaluate microauthd, keep this in mind: Security-first means CPU-first, and we wouldn’t have it any other way.

**2025-06-25**

PKCE (Proof Key for Code Exchange) is now implemented. The example is served up from the public folder. ~~Empty this folder out if you don't want files served from it; I will likely add an option to enable/disable the static file hosting, but it is not implemented yet.~~ Fixed. Now, setting --serve-public-auth-files (or config file or env vars) enables the local webserver to serve static files from the /public subfolder of the microauthd working directory (defaults to false). Files will be served up as the root of the webserver (there will be no /public in the url). This is useful for serving up a simple login page or other static files that you want to be accessible from the auth server. The example login page can be removed to store your own files & assets.

PKCE is a security measure that mitigates the risk of authorization code interception attacks. It is primarily used in OAuth 2.0 and OpenID Connect flows to enhance security, especially for public clients (like mobile or single-page applications) that cannot securely store client secrets. It is similar to a challenge-response system. In the PKCE flow, the client generates a code verifier and a code challenge. The code verifier is a random string, while the code challenge is derived from the code verifier using a transformation method (usually SHA-256). When the client requests an authorization code, it includes the code challenge. Later, when exchanging the authorization code for an access token, the client must provide the original code verifier. The server then verifies that the code verifier matches the code challenge and issues the access token if they match.

**2025-06-24**

Some people are confused about what exactly microauthd is. You would use this instead of the built-in ASP.NET Core Identity system when you need real authentication across multiple platforms — not just a website. microauthd is built for shared login across web, SPA, mobile, and desktop apps, with proper token issuance, refresh, revocation, and machine-to-machine support. It separates identity from UI, so your backend services, CI jobs, and clients all speak the same auth language — without tying your auth logic to Razor Pages or EF Core.

It is important to note that although microauthd is written in C#, it is not tied to ASP.NET Core, or .NET Core at all except needing the .NET 8 runtime to run. It is designed to be used with any platform that can support Json Web Tokens (JWT) and can be used from any language that allows you to issue HTTP POST commands against a web endpoint (basically all of them). Don't be afriad of microauthd if you're not a .NET Core person or your platform is not running on .NET Core. This is quite common as systems like KeyCloak are written in Java and Authentik is written in Python.

~~I am going to begin working on the machinery needed to be reliably hosted behind a reverse proxy. This will include the forwarded headers along with support for trusted proxies. I hope to have this in an working by tomorrow.~~ (Done)

**2025-06-23**

I put together a client library (madAuthClient) to bridge the token-based authentication of microauthd with ASP.NET Core's cookie authentication. This allows you to use microauthd as a drop-in replacement for ASP.NET Core's built-in authentication system, while still using the same token-based authentication that microauthd provides. There is an example project in madRazorExample which uses this library to set up its auth provider.

~~Big changes coming to the audit logger. It was poorly thought out and implemented, so I'm going to be reworking it to use a more structured aproach. The current implementation is static and has no access to the HttpContext which results in many log entries having incorrect (or blank) values for the user id. Time to make it a bona-fide instance class and do it right. I should have the refactor done by tomorrow.~~ Done.

The web-based GUI threw the AOT compilation for a loop; this marks the end of the AOT compilation work for now. It is more important to have a robust web-based GUI than to shave 100ms off of startup time and 10-15MB of memory.

**2025-06-22**

Web-based GUI is available at `http://localhost:9041/Dashboard` (substitute your hostname / port as needed). 

Still working on the web-based management GUI. The Razor Pages implementation is progressing well and should be ready for initial testing soon. The project is a good demonstration of using microauthd's auth capabilities, as it generates all tokens and handles logins for the admin site.

**2025-06-21**

Working on a web-based management GUI. Currently implementing via Razor Pages, which will allow us to create a simple web interface for managing users, roles, permissions, scopes, and clients. About 10% of the way there, but it is a start.

Realized there wasn't an example login flow, so I added a simple example at public/login.html. The public/ folder in microauthd is used to serve static files, such as a login page or documentation. Any files placed in this folder will be available at the root of the AUTH server (e.g., /login.html). By default, login.html is included as a simple authentication interface.

You can customize the login experience by modifying this file or replacing it entirely. During build and publish, the contents of public/ are automatically copied to the output directory and served by the AUTH server.

The contract for the login page is that it should POST to `/token` with the following fields / parameters: grant_type=password, username, password, and client_id (should mirror the client you set up during OOBE). You can also refresh at `/token` with grant_type = refresh_token and token set to the refresh token value obtained with the original token grant.

**2025-06-20**

Started separating the data layer from the service layer internally. This will allow us to swap out the data layer in the future without affecting the service logic. There is currently no plan to abandon SQLite, so this will be an ongoing background process.

We haven't had a lot of time to test the bindings, so please stay tuned for updates on that front. The idea was to get *something* out there for people to use, but we will be actively auditing for full coverage and putting together testsuites for each of the sets of bindings.

**2025-06-19**

Bindings are up for Python, Go, and JS/TS. Please consider all of them a work in progress, but the should be usable for most operations (both AUTH & ADMIN).

So the cli tool `mad` is now in a pretty good state, but it is **slow**. And not just a little slow, but *really* slow. That is fine for the time being, because it is a cli bootstrapping tool mostly, it is not expected that heavy scripting will be done using it. I figure most people will code against the JSON HTTP APIs directly, and those are plenty fast. I just wanted to give people a heads up that the CLI is not fast. Know that it is not microauthd itself.

**2025-06-18**

~~Things are a bit in flux at the moment. Some things are broken.~~ Token introspection and token revocation should be solid again.

~~We are going to be implementing TOTP-based login in the next day or so, so the repo might be in flux for a bit. 0.7.1.4 is a stable release for testing purposes.~~

TOTP-based login is now implemented and will be undergoing testing. Stick at 7.1.4 for now if you want something stable to play with. The way TOTP works is that a request is made to generate a QR code, and then the user has to verify before it is set to active. We also added an endpoint to validate username/password without issuing a token, so expected login flows of validating user/pass and then MFA via TOTP works as generally implemented elsewhere. TOTP can also be disabled via JSON/HTTP API.

Remember please that the database schema is still in flux, and we do not provide migrations yet, so you will need to drop the database and re-run the OOBE wizard. When we go stable, we will begin providing db migrations.

**2025-06-17**

CRUD operations are now implemented for our 5 main data types: users, roles, permissions, clients, and scopes. The API is now consistent across all endpoints, with uniform response structures and error handling. The `mad` CLI tool has also been significantly improved to support these operations.

The python test harness is now complete and has been used to validate the API surface, the back-end functions and the `mad` CLI tool. `mad` can now be used to create, update, delete, and assign users, roles, permissions, clients, and scopes. Additional tests will be added for token grant, revocation and refresh token redemption (all 3 have been tested manually and via script and the system does work as intended).

**2025-06-16**

microauthd is currently not yet ready for production use. It has a LOT of rough edges right now. The code is functional and has been tested in a few scenarios, but it is most definitely not ready for production use. There is no documentation yet, either.

Please read on to understand its current capabilities, design philosophy, real-world security posture, known limitations, and how it will evolve toward a production-ready release.

Understand that this is **NOT A PRODUCTION READY SYSTEM**. It is not even suitable for testing in production-like environments yet. It is a work in progress.

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

- Web-based management GUI is in progress (Razor Pages)
- `mad` CLI still a WIP but has improved significantly
- ~~Some minor inconsistencies in API response formatting~~ (APIs are now consistent)
- Token usage metadata is stored but not yet used for token tracing
- Audit log field consistency still being refined
- Swaggger/OpenAPI coverage is in progress (tags are set but needs polish)

### Known Shortcomings

- ~~**Update Endpoints are not yet implemented**~~ - updates are now implemented for users, roles, permissions, clients, and scopes
- **No multi-tenancy** support (by design)
- ~~**No UI** - this is a text-first, CLI- and API-driven system~~ (In progress)
- **One shared DB connection** limits concurrency- will be addressed via per-request pooled connections
- **Does not enforce fine-graned resource ownership or external ACLs** - leaves this to calling systems
- OOBE is helpful, but **not quite production-ready** for large deployments (much better in v2 of OOBE now)
- ~~OTP-based loginis not yet implemented (on roadmap)~~ (Done)
- **Bindings for Python, Go, and JS/TS are in the repo; other languages are not yet published**

### Project Roadmap

1. ~~Add token introspection endpoint (`/introspect`)~~ Done.
2. ~~Implement replay detection for access tokens~~ Done.
3. Replace shared DB connection with per-request pooling (WAL-mode safe)
4. ~~Clean up API DTOs (uniform `MessageResponse`, consistent `id + name`)~~ Done.
5. ~~Launch test harness using `mad` + Python bindings (in progress)~~ Done.
6. Ship bindings for C# & Rust
7. More robust failed password mechanisms (~~rate limiting~~ (done) / exponential backoff)
8. ~~OTP login flow~~ (Done)
9. Example code for common languages
10. Documentation for all endpoints, CLI, and bindings
---

## Summary

microauthd hopes to get to an alpha-level release in the next few months as a small, secure, and deterministic identity service ideal for embedded control planes, internal APIs, or constrained deployments where full platforms are overkill.

It's not ready for general use today, but we're working diligently to get to an alpha release. The CLI is already (mostly) usable for local testing and automation, and the API surface is stable and predictable.

If you're building a system that needs to embed authentication but doesn't want the overhead or complexity of a Keycloak or Auth0, microauthd may be exactly what you're looking for and it's only getting better from here.
