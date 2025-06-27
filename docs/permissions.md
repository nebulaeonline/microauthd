# microauthd
---
## Permissions
---

#### Introduction

A permission is the smallest unit of access control in microauthd. It defines a single, atomic capability- like:

- `read:users`
- `write:settings`
- `revoke:tokens`

Permissions are **not tied to users directly**- they are assigned to **roles**.

#### Role-Based Assignment Model

Hierarchy:

User <-> Role <-> Permission

- Users are assigned one or more **roles**
- Roles carry one or more **permissions**
- Therefore, **users inherit permissions through roles**

This model:

- Keeps permissions manageable (reuse via roles)
- Supports delegation and tiered access
- Enables scalable, testable, and auditable logic

#### How to Create and Assign Permissions

1. Create a Permission

  - Mad CLI

  ```bash
  mad permission create --name read:users
  ```

  - Admin UI
    - Go to **Permissions** -> Create
    - Name it `read:users` or similar
    - Optionally add a description

2. Assign to a Role

  - Mad CLI

  ```bash
  mad permission assign --role-id <role_id> --permission-id <perm_id>
  ```
  - Admin UI
    - Go to **Roles** -> Edit
    - Click **Assign Permissions**
    - Add the desired Permission(s) to the Role's list of Permissions

3. Assign Role to User

  - Mad CLI

  ```bash
  mad role assign --user-id <user_id> --role-id <role_id>
  ```
  - Admin UI
    - Go to **Users** -> Edit
    - Click **Assign Roles**
    - Add the desired Role(s) to the User's list of Roles

#### How Permissions are Used

microauthd does not hardcode permission meanings- they're freeform strings used in:

1. Authorization Decisions in Your App

  When your app introspects a token, you can enforce logic like:

  ```csharp

    // C#
    if (permissions.Contains("write:settings"))
    {
        // allow update
    }
    else
    {
        return 403;
    }
  ```

  Or:

  ```python
  # Python
  if "read:analytics" not in claims["permissions"]:
    abort(403)
  ```

  You are in full control of the enforcement.