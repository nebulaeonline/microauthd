# microauthd
---
## Admin GUI
---

#### Introduction

The admin GUI is available on the ADMIN host (protocol, ip & port), for example http://localhost:9040/Dashboard. There is no default page, you must navigate to the dashboard yourself directly.

The admin GUI allows the full CRUD spectrum for users, roles, permissions, clients & scopes. The admin GUI is only available to those users that have the `MadAdmin` role.

#### Users

Here you can add new users, edit existing users, soft-delete or hard-delete users, and set users on lockout (permanent or time-based). You can also assign Roles & Scopes directly from the user list.

#### Roles

You can add new roles, edit existing roles, and assign permissions to roles.

#### Permissions

You can add, edit, and delete permissions from these pages

#### Clients

You can add, edit, and delete clients. You can also reset the client secrets and assign scopes to clients.

#### Scopes

YOu can add, edit, and delete scopes.

#### Sessions

From here you can see all active and expired sessions and refresh tokens. You can revoke sessions and refresh tokens (including all by user or individually). You can also purge the sessions and refresh tokens via date and whether the sessions or refresh tokens are expired and/or revoked.

#### Logs

You can view the audit logs here