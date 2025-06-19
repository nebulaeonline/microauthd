# microauthd
---
## Getting Started Guide
---

### Introduction

Setting up an identity provider, even one as small in scope as microauthd, can be complicated. One of our primary goals is to make this process as painless as possible so you can focus on your actual project and not on all of the intricacies of auth, role delegation, permissions, and scopes.

When you run microauthd for the first time, you'll be greeted by an interactive Out-of-Box Experience (OOBE) that guides you through bootstrapping your installation.

You can think of it like an installation wizard — but terminal-based, fast, and security-focused.

### What OOBE Does

The OOBE handles the minimum required steps to get a secure, working instance:

- Configures your database and writes a config file
- Sets up TLS certs (if desired), logging, and token signing keys
- Prompts you to create an admin user
- Creates your first OIDC client

Once finished, you're ready to start using the system via the CLI (`mad`) or REST API.

### Walkthrough: What You'll be Asked

Here are the steps, what they mean, and what your answers affect:

#### Database File and Password

*Please enter the full path to your desired database file*

- This is where your data will live (users, clients, tokens, sessions, etc.)
- If you specify a password, the DB will be encrypted (SQLite + AES)

#### Full Guided Setup?

*Do you want to do a full guided setup?*

- If you say yes, you'll be asked about logging, key lengths, etc.
- If you say no, you'll only do the minimal required steps:

    - DB Setup
    - Admin Account
    - One OIDC client

#### Config and Logging Paths

*Where should the config file live?*

- Choose where mad.conf is written
- Log file path is also prompted (e.g. `logs/microauthd.log`)

#### Server Bind Addresses

You'll be asked to configure two servers:

- AUTH Server

    - Port: typically 9040
    - This is the public-facing server (e.g. `/token`, `/introspect`)
    - May serve HTTPS with cert + password

- ADMIN Server

    - Port: typically 9041
    - Internal use only - requires admin tokens
    - Used by the `mad` CLI and for trusted automation

You'll also specify your external domains for each, and whether those external domains are HTTP or HTTPS (for token `issuer` fields).

#### Argon2 Password Hashing Parameters

- These define how secure password and secret storage will be
- Defaults are strong and exceed current OWASP recommendations; advanced users can tune:

    - Time cost
    - Memory usage
    - Parallelism

#### Token Signing Key Setup

- You'll generate RSA or EC keys for signing tokens
- Prompts you for:

    - Key file paths
    - Whether to use EC (more efficient)
    - RSA key lengths (if not EC)
    - Optional key passphrases

You'll configure this separately for AUTH and ADMIN keys

#### Token Expiration Settings

- Choose expirations for:

    - Access tokens
    - Admin tokens
    - Refresh tokens (if enabled)

#### Feature Flags

- Choose whether to enable:

    - Token revocation (via blacklist or session invalidation)
    - Refresh tokens (long-lived sessions)
    - OTP (TOTP) login (can also be setup later)
    - Audit logging and how many days to retain logs

#### Login Security Settings

- Max failed login attempts before lockout
- Lockout duration (seconds)
- How long to wait before resetting failure counters

#### OIDC Client

- You'll be asked to generate a default client (e.g. `app`)
- A strong secret is generated
- This is useful for CLI automation or service-to-service access

#### Admin Account

- Required
- You'll set:

    - Username
    - Email
    - Password

- This account gets the built-in `MadAdmin` role

---

## What Happens After OOBE

Once complete:

- A working `mad.conf` file is written
- SQLite DB is created and optionally encrypted
- Signing keys are generated
- Admin user and OIDC client are created

You can now run:

```bash
mad session login --admin-url http://localhost:9041
mad user list --admin-url http://localhost:9041
```

...Or start issuing tokens using the `/token` endpoint on the AUTH server.

### Where Things Are Stored

| File                               | Purpose                 |
|------------------------------------|-------------------------|
| `mad.conf`                         | Your config file        |
| `mad.db3`                          | Your SQLite Database    |
| `token.pem`                        | Token signing key       |
| `token.pub.pem`                    | Token public key        |
| `admin_token.pem`                  | Admin token signing key |
| `admin_token.pub.pem`              | Admin token public key  |
| `microauthd.log`                   | Log file                |


### Pro Tip

You can re-run OOBE by deleting the DB file. It is also recommended to delete the 4 key files (token & admin token signing & public keys)
