# microauthd
---
## Clients
---

#### Introduction

For those unfamiliar with the terminology of authentication, a Client in microauthd represents an external system or application that interacts with your identity server. It's a formal identity used to:

- Authenticate to /token
- Request user authorization (PKCE)
- Receive scoped access tokens or ID tokens

The client id (client_identifier) is a unique string that identifies the client. Often named after the app or consumer. 

Whether it's a web app, mobile app, CLI tool, server-to-server backed- everything that wants a token is a client. It's a concept that is core to OAuth2.

microauthd supports an arbitrary number of clients. You are free to create and use them as you see fit for your deployment. 

The client secret is:

- Used in `password` and `refresh_token` grants
- Must be stored securly by the client
- Can be auto-generated in microauthd via
  - The Admin UI (via the Regenerate Client Secret button)
  - The OOBE bootstrap wizard
  - The CLI tool `mad` via `mad client create`'s --gen-password option

Once generated, the client secret *cannot be viewed again*. Treat it like a password.

*Flows Supported*

| Flow                        | Requires client secret | Requires redirect URIs | Requires PKCE |
|-----------------------------|------------------------|------------------------|---------------|
| Password grant              |        Yes             |         No             |      No       |
| Refresh token               |        Yes             |         No             |      No       |
| Client Credentials          |        Yes             |         No             |      No       |
| Authorization Code (PKCE)   |        No              |        Yes             |     Yes       |

#### Redirect URIs

Redirect URIs are URIs that have been set specifically on a client object as being an allowed location to redirect the user to. These are verified, and microauthd will not issue a redirect to a URI that is not specifically whitelisted. Redirect URIs are used in the Proof Key for Code Exchange (PKCE) flow, which does not require the client secret. This is the flow used when the client cannot store the client secret (i.e. in a webpage where source code is available to end users). 

Redirect URIs

- Are required for PKCE flow
- Must be pre-registered for the client
- Validation is *strict*:
  - Exact match
  - Case sensitive
  - Must match domain & path
- Managed via
  - Admin UI
  - Mad CLI
  - JSON/HTTP interface

#### Client Audience

What is the Audience?

The audience (`aud` claim in JWTs), defines *who* a token is intended for.

- It is a required claim in microauthd tokens
- It is *validated* both at issue time and at introspection
- Prevents tokens from being reused or misused across different services

**Audience = Token Target**

Think of audience like a named permission domain:

If `aud = "myapp"`, then:

  - Only `"myapp"` should accept this token
  - Other services (e.g. `"analytics"`) must reject it

This protects you from:

  - Cross-service token misuse
  - [Confused deputy](https://en.wikipedia.org/wiki/Confused_deputy_problem) attacks
  - Replay risks in microservice environments

**Setting the Audience**

You must set the audience when registering a client.

  - Admin UI: Set during creation or update
  - `mad` cli:

```bash
mad client create --client-id app1 --audience app1 --secret supersecret
```

  - OOBE Setup: prompts you to assign audience to the default (first) client

**Where Audience is Used**

1. Token issuance:
  - Every JWT includes `aud: client.audience`
  - ID Tokens too
2. Token validation:
  - If you introspect or parse tokens externally, *your system must* validate `aud`
3. Client credentials grant:
  - Use `audience` to scope backend access
  - Think of it as a virtual permission domain

**Best Practices**

- Match the audience to your actual API/Service name
- Don't reuse audience values across unrelated services
- Consider validating `aud` in your downstream apps (if not using introspection)
