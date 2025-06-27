# microauthd
---
## Roles
---

#### Introduction

In microauthd, **roles** are a fundamental building block for **your** access control- we only take one role and that is the gating of the `ADMIN` side only to users with the `MadAdmin` role. Everything else is up to you. A role is nothing more than a named grouping of permissions, designed to make access delegation clear, auditable, and reusable.

You are responsible for enforcing your Role & Permission system, we just make sure the structure is there and the tools to manage it is there; it is envisioned that your software will make heavy use of the JSON/HTTP API in order to "drive" microauthd. It's job is to validate passwords and issue tokens, and to do so in a secure manner. Your job is to write the software that makes use of the provided mechanisms (or doesn't).

Basically if you need to only feature gate users, use a permission (or group of permissions) and a Role. If you need a specific capability to be available to both Users & Clients, use a scope. At the end of the day they are all permissions.