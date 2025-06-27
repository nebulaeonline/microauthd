# microauthd
---
## Scopes
---

#### Introduction

What is a scope? A **scope** in microauthd is a named string that expresses a boundary of access- typically one or more permissions or actions that a client can request or be granted.

In line with OAuth2/OIDC conventions, scopes are:

- Attached to **clients** (what they're allowed to request)
- Assigned to **users** (what they're allowed to inherit)
- Included in **tokens** (as the `scope` claim)

They're consumed by apps and APIs to determine what capability the caller has.

#### Scope Management

Scopes can be:

- Created/edited/deleted via:
  - `mad` CLI (`mad scope ...`)
  - Admin Web Interface
  - JSON/HTTP API

- Assigned to:
  - Users directly
  - Clients (for default scopes)

- Queried in `mad` CLI using:
  - `scope list-for-user`
  - `scope list-for-client`

#### Built-in / Hardcoded Scopes

microauthd includes several system-defined scopes that exist specifically to provide limited, secure functionality on the AUTH server — without requiring access to the privileged ADMIN API.

These scopes are designed for:

  - External software (e.g. portals, apps, orchestrators)
  - Self-service features (e.g. resetting a user's password)
  - Minimal-privilege delegation
  - Not intended for administrative use


| Constant              | Value (UUID)        |  Friendly Name |
|-----------------------|---------------------|----------------|
| Scope_ProvisionUsers	| d0955db1-67f7-4a7b-a9bb-ffbef4f0d2bd |admin::provision_users  |
| Scope_ResetPasswords  | 2192998b-c3d3-4274-9a25-4a4195ba2ec7 |admin::reset_passwords  |
| Scope_DeactivateUsers	| 31c00aae-4136-4a8c-92a6-d2bbf4be2d35 |admin::deactivate_users |
|Scope_ReadUser	        | 1f4610fe-0cb2-4119-bd69-9b6033326998 |admin::read_user        |
|Scope_ListUsers	    | b6348575-83ec-4288-801b-e0d2da20569c |admin::list_users       |

**Why Use These?**

Because the `ADMIN` API is protected by:

  - Separate JWT signing keys
  - Role-based access (`MadAdmin` only)

  ... it is inappropriate to expose it to user-facing or partner-facing software. Instead, the `AUTH` server exposes safe operations gated by the above scopes.

  **Examples**

| Scope Constant	  | Action Enabled                             |
|---------------------|--------------------------------------------|
|Scope_ProvisionUsers |Allows a service to create new user accounts|
|Scope_ResetPasswords |Allows triggering a password reset flow     |
|Scope_DeactivateUsers|Allows disabling a user account cleanly     |
|Scope_ReadUser	      |Allows reading user info (e.g. email, flags)|
|Scope_ListUsers	  |Allows listing user summaries               |

**Common Use Case: Portal-Only Access**

Suppose you're building a support portal that lets internal staff:

  - View user accounts
  - Reset passwords
  - Disable logins

You do **not** want to:

  - Expose admin keys
  - Allow full user enumeration
  - Permit role assignments

Instead:

  - Assign a client these specific scopes
  - Tokens will contain the scope values
  - The portal can introspect and check them
  - Backend handlers on the AUTH server allow only what’s scoped

**Security Model**

These scopes:

  - Are stored as UUIDs internally for immutability
  - Can be assigned to users or clients like any scope
  - Are intended to be guardrails, not just decoration

**Important**

  - Do not expose ADMIN tokens to third parties
  - These AUTH-bound scopes do not require MadAdmin
  - They support the principle of least privilege

**Why Scopes and Not Permissions?**

Functional Needs:

For these capabilities, we wanted to allow:

  - Assignment to both users and clients
  - Use in OAuth2 access tokens
  - Secure gating of specific capabilities (e.g. reset password)
  - Simple integration paths for external systems

Permissions in microauthd are designed to:

  - Be role-based
  - Affect administrative behavior
  - Not show up in JWTs by default
  - That doesn’t fit this use case.

**Integration Philosophy**

This gives integrators full control:

  - Want to build a support dashboard? Assign Scope_ListUsers.
  - Want a self-service app to let users reset other accounts? Assign Scope_ResetPasswords.
  - Want to keep users isolated? Don’t assign any of these scopes.

It’s flexible **by design**