# microauthd
---
## AUTH Endpoints (this doc is currently a WIP)

These are the endpoints that are available via the AUTH side of the microauthd server. In microauthd, all endpoints should be considered PRIVATE unless otherwise indicated (i.e. they require a valid, unexpired bearer token to be granted access).

**OCC1** as used in this reference refers to the [OpenId Connect Core 1.0 Specification (incorporating errata set 2)](https://openid.net/specs/openid-connect-core-1_0.html).

The OAuth 2.0 Authorization Framework, generally referred to as **OAuth2** herein, refers to [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749).

## Table of Contents

### Miscellaneous Endpoints
[Ping](#ping)
[Version](#version)
[Antiforgery](#antiforgery)
[User Info](#user-info)
[Me](#me)
[Me Sessions](#me-sessions)
[Me Refresh Tokens](#me-refresh-tokens)
[Who Am I?](#who-am-i)

### PKCE Endpoints
[Authorize](pkce-authorize)
[Authorize UI](pkce-authorize-ui)
[Handle UI Login](pkce-handle-ui-login)

---

#### Ping

The Ping endpoint is PUBLIC

The Ping endpoint is for clients to verify connectivity to the microauthd AUTH server.

|Endpoint | Inputs | Outputs |
|---------|--------|---------|
|/ping    | None   | PingResponse |

PingResponse:

{
&nbsp;&nbsp;&nbsp;&nbsp;"message": "pong from auth"
}

---

#### Version

The Version endpoint is PUBLIC

The Version endpoint is for clients to ascertain the current version of microauthd the AUTH server is running.

|Endpoint | Inputs | Outputs |
|---------|--------|---------|
|/version    | None   | VersionResponse |

VersionResponse:

{
&nbsp;&nbsp;&nbsp;&nbsp;"name"    : "microauthd",
&nbsp;&nbsp;&nbsp;&nbsp;"version" : "current version number string"
}

---

#### Antiforgery

The Antiforgery endpoint is PUBLIC

The antiforgery endpoint uses .NET Core's built-in machinery to issue CSRF tokens which are used in PKCE flow logins.

|Endpoint | Inputs | Outputs |
|---------|--------|---------|
|/antiforgery    | None   | CSRF Token |

---

#### User Info

The User Info endpoint is required by OCC1 Section 5.3.2, and is considered a Protected Resource under OAuth2 standards. Its purpose is to return one or more Standard Claims, as defined in OCC1 Section 5.1.

/userinfo in microauthd returns the following claims from the presented token (if they exist):

- NameIdentifier / Sub (user GUID)
- Iss (issuer)
- Aud (audience)
- Email
- Email Verified
- Name
- Username
- Preferred Username

|Endpoint | Inputs | Outputs |
|---------|--------|---------|
|/userinfo    | None   | Certain Standard claims |

---

#### Me

The Me endpoint is non-standard vestige from microauthd's earlier days. It is retained for sentimental purposes. It is used to return basic information about the current user.

/me returns the following claims from the presented token (if they exist):

- NameIdentifier / Sub (user GUID)
- Email
- User Roles
- User Scopes

|Endpoint | Inputs | Outputs |
|---------|--------|---------|
|/me    | None   | MeResponse |

MeResponse:

{
&nbsp;&nbsp;&nbsp;&nbsp;"sub"    : "user GUID",
&nbsp;&nbsp;&nbsp;&nbsp;"email"  : "user email",
&nbsp;&nbsp;&nbsp;&nbsp;"roles"  : [ "role1", "role2", ... ],
&nbsp;&nbsp;&nbsp;&nbsp;"scopes" : [ "scope1", "scope2", ... ],
}

#### Me Sessions

The Me Sessions endpoint is used to return a list of the current user's sessions in the system (active, inactive & revoked) ordered newest to oldest.

|Endpoint | Inputs | Outputs |
|---------|--------|---------|
|/me/sessions    | None   | List&lt;SessionResponse&gt; |

SessionResponse:

{
&nbsp;&nbsp;&nbsp;&nbsp;"id"         : "session GUID",
&nbsp;&nbsp;&nbsp;&nbsp;"user_id"    : "user GUID",
&nbsp;&nbsp;&nbsp;&nbsp;"username"   : "username",
&nbsp;&nbsp;&nbsp;&nbsp;"client_id"  : "client identifier (note: NOT GUID),
&nbsp;&nbsp;&nbsp;&nbsp;"issued_at"  : "when the session was started",
&nbsp;&nbsp;&nbsp;&nbsp;"expires_at" : "when the session expires / expired",
&nbsp;&nbsp;&nbsp;&nbsp;"is_revoked" : "whether the session is revoked or not",
&nbsp;&nbsp;&nbsp;&nbsp;"token_use"  : "access or id",
&nbsp;&nbsp;&nbsp;&nbsp;"mad_use"    : "admin or auth"
}

---

#### Me Refresh Tokens

The Me Refresh Tokens endpoint is used to return a list of the current user's refresh tokens in the system (active, inactive & revoked) ordered newest to oldest.

|Endpoint | Inputs | Outputs |
|---------|--------|---------|
|/me/refresh-tokens    | None   | List&lt;RefreshTokenResponse&gt; |

RefreshTokenResponse:

{
&nbsp;&nbsp;[
&nbsp;&nbsp;&nbsp;&nbsp;"id"         : "session GUID",
&nbsp;&nbsp;&nbsp;&nbsp;"user_id"    : "user GUID",
&nbsp;&nbsp;&nbsp;&nbsp;"username"   : "username",
&nbsp;&nbsp;&nbsp;&nbsp;"session_id" : "session GUID it belongs to"
&nbsp;&nbsp;&nbsp;&nbsp;"client_id"  : "client identifier (note: NOT GUID),
&nbsp;&nbsp;&nbsp;&nbsp;"issued_at"  : "when the session was started",
&nbsp;&nbsp;&nbsp;&nbsp;"expires_at" : "when the session expires / expired",
&nbsp;&nbsp;&nbsp;&nbsp;"is_revoked" : "whether the session is revoked or not",
&nbsp;&nbsp;&nbsp;&nbsp;"is_openid_token" : "whether this was issued as part of an OIDC request"
&nbsp;&nbsp;]
}

---

#### Who Am I

The Who Am I endpoint is just a simple endpoint that returns "Hello, {user GUID}"

|Endpoint | Inputs | Outputs |
|---------|--------|---------|
|/me/whoami    | None   | "Hello, {User GUID}" |

---

#### PKCE Authorize

The Authorize endpoint is PUBLIC.

The PKCE Authorize endpoint is the first step in a PKCE login flow that requires no login ui, so is useful for CLI clients or services. 

In this flow, the client sends a client id, a redirect uri, a response_type of "code", plus a code challenge and a code challenge method; the client can also choose to send an optional state parameter, as well as a nonce too. 

If the client id is valid and the redirect uri is registered to that client, microauthd will respond with a redirect and the code and the state & nonce (if supplied), along with an authorization code tied to the challenge. The user then authenticates using username & password (and optionally TOTP), while providing the code, the code verifier, and the authorization code.

At this point microauthd will mark that the authorization code belongs to the user that authenticated, and the user may, at that point, present the authentication code to the /token endpoint to receive an access token.

Generally PKCE flow is used for clients that cannot, for technical reasons or other, safely store a client secret to use the traditional login flow.

|Endpoint | Inputs | Outputs |
|---------|--------|---------|
|/authorize    | response_type   | Redirect + code & state |
|              | client_id       | |
|              | redirect_uri    | |
|              | scope           | |
|              | state           | |
|              | code_challenge  | |
|              | code_challenge method       | |
|              | nonce       | |

---

#### PKCE Authorize UI

The PKCE Authorize UI endpoint is PUBLIC.

The PKCE Authorize UI endpoint is the first step in a PKCE login flow that uses a login ui, so is useful for webpages and mobile applications.

In this flow, the client sends a client_id and a redirect_uri, and if the redirect uri is valid for the specified client, microauthd will store the values from the query string and generate a jti for the login session. It will then send a redirect to the redirect uri where the client will need to authenticate while providing the jti.

Once authenticated, an authorization code is issued which the client can exchange for a valid token at the /token endpoint.

|Endpoint | Inputs | Outputs |
|---------|--------|---------|
|/authorize-ui    | client_id   | Redirect + code & state |
|              | redirect_uri    | |

---

#### PKCE Handle UI Login

The /login-ui endpoint is step two of the UI-based login procedure. The client provides their username & password along with the jti from /authorize-ui. If the credentials match, a code will be provided that can then be redeemed for a token.

|Endpoint | Inputs | Outputs |
|---------|--------|---------|
|/login-ui    | username   | Redirect + code & state |
|              | password    | |
|              | jti    | |

---

#### PKCE Auth Session

This endpoint is used between steps 1 and 2 of the login ui process; its purpose is to retrieve the query string that was associated with a jti in step 1 (it is essentially hydrating step 2). 

|Endpoint | Inputs | Outputs |
|---------|--------|---------|
|/auth_session    | jri   | the session object |

---

#### 