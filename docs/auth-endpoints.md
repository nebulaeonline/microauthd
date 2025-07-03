# microauthd
---
## AUTH Endpoints (this doc is currently a WIP)

These are the endpoints that are available via the AUTH side of the microauthd server. In microauthd, all endpoints should be considered PRIVATE unless otherwise indicated (i.e. they require a valid, unexpired bearer token to be granted access).

**OCC1** as used in this reference refers to the [OpenId Connect Core 1.0 Specification (incorporating errata set 2)](https://openid.net/specs/openid-connect-core-1_0.html).

The OAuth 2.0 Authorization Framework, generally referred to as **OAuth2** herein, refers to [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749).

## Table of Contents

### Miscellaneous Endpoints

[Ping Endpoint](#ping)  
[Version Endpoint](#version)  
[Antiforgery Endpoint](#antiforgery)  
[User Info Endpoint](#user-info)  
[Me Endpoint](#me)  
[Me Sessions Endpoint](#me-sessions)  
[Me Refresh Tokens Endpoint](#me-refresh-tokens)  
[Who Am I? Endpoint](#who-am-i)  

### PKCE Endpoints

[PKCE Introduction](#pkce-introduction)  
[PKCE Authorize Endpoint](#pkce-authorize)  
[PKCE Authorize UI Endpoint](#pkce-authorize-ui)  
[PKCE Handle UI Login Endpoint](#pkce-handle-ui-login)  
[PKCE Login Endpoint](#pkce-login)  

### Logout Endpoints

[Logout Endpoint](#logout)  
[Logout All Endpoint](#logout-all)  

### OIDC Client Token Endpoint

[Issue OIDC Token Endpoint](#oidc-client-tokens)  

### Scoped Endpoints

[Create User Endpoint](#scoped-create-user)  
[Reset User Password Endpoint](#scoped-reset-user-password)  
[Deactivate User Endpoint](#scoped-deactivate-user)  
[List Users Endpoint](#scoped-list-users)  

### Utility Endpoints
[Introspect Endpoint ](#introspect)  
[Revoke Endpoint](#revoke)  

---

#### Ping

The Ping endpoint is PUBLIC

The Ping endpoint is for clients to verify connectivity to the microauthd AUTH server.

|Endpoint | Inputs | Outputs |
|---------|--------|---------|
|GET /ping    | None   | PingResponse |

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
|GET /version    | None   | VersionResponse |

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
|GET /antiforgery    | None   | CSRF Token |

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
|GET /userinfo    | None   | Certain Standard claims |

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
|GET /me    | None   | MeResponse |

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
|GET /me/sessions    | None   | List&lt;SessionResponse&gt; |

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
|GET /me/refresh-tokens    | None   | List&lt;RefreshTokenResponse&gt; |

RefreshTokenResponse:

{  
&nbsp;&nbsp;[  
&nbsp;&nbsp;&nbsp;&nbsp;"id"         : "session GUID",  
&nbsp;&nbsp;&nbsp;&nbsp;"user_id"    : "user GUID",  
&nbsp;&nbsp;&nbsp;&nbsp;"username"   : "username",  
&nbsp;&nbsp;&nbsp;&nbsp;"session_id" : "session GUID it belongs to"  
&nbsp;&nbsp;&nbsp;&nbsp;"client_id"  : "client identifier (note: NOT GUID)",  
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
|GET /me/whoami    | None   | "Hello, {User GUID}" |

---

#### PKCE Introduction

microauthd supports two complete PKCE flows for secure login without requiring clients to store a secret. These flows are designed for slightly different use cases, but both conform to the OAuth2 and OpenID Connect standards. The first is a headless flow initiated via /authorize, intended for CLI apps or services. The second is a login-UI flow built on top of /authorize-ui, which introduces an interactive login experience.

**Flow 1: Headless PKCE (CLI / Services)**

In the headless flow, the client initiates authentication by making a call to /authorize, supplying a client identifier, redirect URI, response_type=code, a code challenge, and a code challenge method (usually S256). The client may also include optional state and nonce parameters, as specified by OCC1 Section 3.1.2.1.

Once microauthd validates that the redirect URI matches what is registered to the client, it responds with a redirect to that URI, embedding the authorization code, and optionally, the state and nonce.

At this point, the client presents a login interface of its own choosing. It prompts the user for a username, password, and optionally a TOTP code. Then, using the original code, the client sends a POST request to /login, along with the code_verifier (matching the challenge), username, password, and client credentials. If everything checks out, the authorization code becomes bound to the user account, and a final request to /token completes the flow—returning an access token and (if openid was requested) an ID token.

This flow is powerful for clients that are fully decoupled from the user interface and cannot safely store secrets, such as CLI tools, native desktop apps, or embedded systems.

**Flow 2: UI-Based PKCE (Login Page)**

The second flow follows the same standards, but with a built-in UI experience.

Here, the client initiates the flow by redirecting the user to /authorize-ui, passing the same set of parameters as before: client_id, redirect_uri, response_type=code, a code_challenge, and the method. Rather than immediately responding with a redirect, microauthd stores the query in a short-lived session (via auth_sessions) and redirects the user to a login page: /login.html?jti=....

On this page, the JavaScript frontend loads the session via the JTI and reconstructs the original request. It displays a standard login form, and when submitted, sends a POST request to /login-ui along with the code, code verifier, and user credentials.

If successful, the backend binds the authorization code to the authenticated user and redirects the user to the original redirect_uri, just as in the headless flow. The client completes the flow by exchanging the code for tokens via the /token endpoint.

This flow is ideal for SPAs or other frontend-driven apps where the authentication is expected to occur in-browser with a clean, polished login interface—without requiring the application to maintain its own auth form.

PKCE endpoints are only enabled if PKCE is enabled.

---

#### PKCE Authorize

The Authorize endpoint is PUBLIC.

The PKCE Authorize endpoint is the first step in the headless PKCE login flow. 

|Endpoint | Inputs | Outputs |
|---------|--------|---------|
|GET /authorize    | response_type   | Redirect + code & state |
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

The PKCE Authorize UI endpoint is the first step in the UI-based PKCE login flow.

|Endpoint | Inputs | Outputs |
|---------|--------|---------|
|GET /authorize-ui    | client_id   | jti |
|              | redirect_uri    | |

---

#### PKCE Handle UI Login

The Handle UI Login Endpoint is PUBLIC.

The /login-ui endpoint is step two of the UI-based login procedure. The client provides their username & password along with the jti from /authorize-ui. If the credentials match, a code will be provided that can then be redeemed for a token.

|Endpoint | Inputs | Outputs |
|---------|--------|---------|
|POST /login-ui    | username   | Redirect + code & state |
|              | password    | |
|              | jti    | |

---

#### PKCE Auth Session

The PKCE Auth Session Endpoint is PUBLIC.

This endpoint is used during step 2 of the UI-based login procedure; its purpose is to retrieve the query string that was associated with the jti in step 1 (it is essentially hydrating the page in preparation for the next step). 

|Endpoint | Inputs | Outputs |
|---------|--------|---------|
|GET /auth_session    | jti   | the session object |

---

#### PKCE Login

The PKCE Login Endpoint is PUBLIC.

The /login endpoint is used in the headless PKCE flow as the actual authentication mechanism. The client must supply a username, password, code, redirect uri, scope and nonce. If everything checks out, the user it attached to the PKCE code, and can then exchange their code for a token at the /token endpoint.

|Endpoint | Inputs | Outputs |
|---------|--------|---------|
|POST /login    | response_type   | MessageResponse |
|              | client_id       | ErrorResponse   |
|              | redirect_uri    | |
|              | scope           | |
|              | code  | |
|              | nonce       | |

MessageResponse:
{  
&nbsp;&nbsp;&nbsp;&nbsp;"success" : "true",  
&nbsp;&nbsp;&nbsp;&nbsp;"message" : "what action was successful"  
}  

ErrorResponse:

{  
&nbsp;&nbsp;&nbsp;&nbsp;"success" : "false",  
&nbsp;&nbsp;&nbsp;&nbsp;"message" : "info about the request that failed"  
}  

---

#### Token

The Token Endpoint is Public

The token endpoint supports three types of grants, and the information required to be passed varies based on whether you are doing a password grant, a refresh grant, or a code grant.

For a password grant, the client must send a username, a password, a client identifier and the client secret. If everything checks out, a bearer token is returned, optionally with an id token if the calling scope contained "openid".

In the refresh token grant, the client must send the refresh token, a client identifier and the client secret. If everything checks out, a bearer token is returned, again, optionally with an id token if the calling scope contained "openid".

In the code grant, the client must send the code, the client id, the code verifier and a redirect url. If everything checks out (i.e. the code & challenge are valid, the code is valid and attached to that user, and the redirect uri is registered to the supplied client id), a bearer token is returned, again, optionally with an id token if the calling scope contained "openid".

|Endpoint | Inputs | Outputs |
|---------|--------|---------|
|POST /token    | various   | Token |

---

#### Logout

The logout endpoint does not require a subject body. This will log the user out of the existing session only. Refresh tokens remain valid.

|Endpoint | Inputs | Outputs |
|---------|--------|---------|
|POST /logout    | none   | none |

---

#### Logout All

The logout-all endpoint does not require a subject body. This will log the user out of every session, and will also invalidate any current refresh tokens that may have been issued.

|Endpoint | Inputs | Outputs |
|---------|--------|---------|
|POST /logout-all    | none   | none |

---

#### Issue OIDC Token

The OIDC Token Endpoint is PUBLIC.

This endpoint supports a "grant_type" of "client_credentials" and is used to log in as a client rather than a user. The client_id (nee Identifier) and client_secret must be passed along with the grant_type. If the credentials are valid, and OIDC client token will be issued.

|Endpoint | Inputs | Outputs |
|---------|--------|---------|
|POST /oidc-token    | grant_type   | Token |
|               | client_identifier |  |
|               | client_secret     |  |

---

#### Scoped Create User

The Scoped Create User Endpoint is one of the delegated ADMIN functions that can be performed from the AUTH side if the user is properly credentialed- i.e. has the Scope_ProvisionUsers (d0955db1-67f7-4a7b-a9bb-ffbef4f0d2bd).

|Endpoint | Inputs | Outputs |
|---------|--------|---------|
|POST /user    | CreateUserRequest   | UserObject |

CreateUserRequest:

{  
&nbsp;&nbsp;&nbsp;&nbsp;"username" : "username",  
&nbsp;&nbsp;&nbsp;&nbsp;"email"    : "email",  
&nbsp;&nbsp;&nbsp;&nbsp;"password" : "password"  
}  

UserObject:

{  
&nbsp;&nbsp;&nbsp;&nbsp;"id"        : "user GUID",  
&nbsp;&nbsp;&nbsp;&nbsp;"username"  : "username",  
&nbsp;&nbsp;&nbsp;&nbsp;"email"     : "email",  
&nbsp;&nbsp;&nbsp;&nbsp;"created_at": "created at",  
&nbsp;&nbsp;&nbsp;&nbsp;"lockout_until" : "locked out until",  
&nbsp;&nbsp;&nbsp;&nbsp;"is_active" : "is the user active?",  
&nbsp;&nbsp;&nbsp;&nbsp;"email_verified" : "is the user's email verified?"  
}  

---

#### Scoped Reset User Password

The Scoped Reset User Password Endpoint is one of the delegated ADMIN functions that can be performed from the AUTH side if the user is properly credentialed- i.e. has the Scope_ResetPasswords (2192998b-c3d3-4274-9a25-4a4195ba2ec7).

|Endpoint | Inputs | Outputs |
|---------|--------|---------|
|POST /user/{id}/reset    | ResetPasswordRequest   | MessageResponse or ErrorResponse |

---

#### Scoped Deactivate User

The Scoped Deactivate User Endpoint is one of the delegated ADMIN functions that can be performed from the AUTH side if the user is properly credentialed- i.e. has the Scope_DeactivateUsers (31c00aae-4136-4a8c-92a6-d2bbf4be2d35).

|Endpoint | Inputs | Outputs |
|---------|--------|---------|
|POST /user/{id}/deactivate    |None   | MessageResponse or ErrorResponse |

---

#### Scoped List Users

The Scoped List Users Endpoint is one of the delegated ADMIN functions that can be performed from the AUTH side if the user is properly credentialed- i.e. has the Scope_ListUsers (b6348575-83ec-4288-801b-e0d2da20569c).

|Endpoint | Inputs | Outputs |
|---------|--------|---------|
|GET /users    |None   | List<UserObject> or ErrorResponse |

---

#### Introspect

The introspect function will take the supplied bearer token and return a dictionary of the claims contained therein.

|Endpoint | Inputs | Outputs |
|---------|--------|---------|
|POST /introspect    |None   | Dictionary<string, object> or ErrorResponse |

---

#### Revoke

The revoke endpoint will revoke the current user's session along with any refresh token that is associated with that session. This is a destructive endpoint.

|Endpoint | Inputs | Outputs |
|---------|--------|---------|
|POST /revoke    |None   | MessageResponse or ErrorResponse |