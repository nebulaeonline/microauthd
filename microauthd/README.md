# microauthd

---

## INTRODUCTION

Microauthd is a lightweight authentication daemon for managing users, sessions, and tokens. It supports multiple 
authentication methods including password-based, token-based, and one-time password (OTP).

Clients can interact with microauthd via HTTP, making it compatible with any language or platform. It supports 
JWT (JSON Web Tokens), optional OpenID Connect (OIDC), and is backed by an embedded SQLite database with optional 
SQLCipher support for encrypted credentials.

While SSL termination is supported for both authentication and administration endpoints, it's strongly recommended 
to run microauthd behind a reverse proxy like Nginx, Apache, or Caddy for TLS handling.

The service is designed to be:

- Secure (Argon2id password hashing, JWT signing)
- Minimal (low memory and CPU usage)
- Deployable (single binary, cross-platform, AOT support)
- Configurable (CLI, environment, config file)

Microauthd supports user roles for fine-grained access control. The only built-in role is `MadAdmin`, which grants 
administrative access. Custom roles can be created through the admin interface, CLI, or API.

---

## GETTING STARTED

Microauthd is available as:

- AOT-compiled binaries (Windows, Linux, macOS)
- A .NET 8 portable build for environments without AOT
- A Docker image (`linux/amd64`) for containerized deployments

Source code is available on GitHub:  
**https://github.com/nebulaeonline/microauthd**

License: MIT

---

##CONFIGURATION

Microauthd can be configured via:

1. Command-line options
2. Environment variables (prefixed, e.g., `MAD_`)
3. INI-style configuration file (e.g., `mad.conf`)

**Order of precedence:**

1. Command-line overrides everything  
2. Environment variables override config file  
3. Configuration file provides defaults

**Configuration File Notes:**

- Default file: `mad.conf` in the working directory
- Format: simple `key = value`, with `#` or `;` for comments
- Permissions: recommended `0600` on production systems

---

##ENVIRONMENT VARIABLE PREFIXING

Use `--env-var-prefix` to isolate instances on the same host.  
Default prefix is `MAD_`.

Example:

export ENV1_MAD_DB_FILE=instance1.db3
microauthd --env-var-prefix ENV1_MAD_

---

##DATABASE CONFIGURATION

| Option      | Description                          | Default     |
|-------------|--------------------------------------|-------------|
| db-file     | SQLite or SQLCipher database path    | mad.db3     |
| db-pass     | Password for the database            | (required unless `no-db-pass`) |
| no-db-pass  | Disable DB encryption                | false       |

---

##AUTHENTICATION SERVER CONFIGURATION

| Option         | Description                        | Default       |
|----------------|------------------------------------|---------------|
| auth-ip        | Listening IP                       | 127.0.0.1     |
| auth-port      | Listening port                     | 9040          |
| auth-domain    | Expected domain                    | localhost     |
| auth-use-ssl   | Use TLS (standalone)               | false         |
| auth-ssl-cert  | SSL certificate path               | auth.pem      |
| auth-ssl-pass  | SSL private key passphrase         | (optional)    |

---

##ADMINISTRATION SERVER CONFIGURATION

| Option         | Description                        | Default       |
|----------------|------------------------------------|---------------|
| admin-ip       | Listening IP                       | 127.0.0.1     |
| admin-port     | Listening port                     | 9041          |
| admin-domain   | Expected domain                    | localhost     |
| admin-use-ssl  | Use TLS (standalone)               | false         |
| admin-ssl-cert | SSL certificate path               | admin.pem     |
| admin-ssl-pass | SSL private key passphrase         | (optional)    |

---

##ARGON2ID HASHING CONFIGURATION

| Option                | Description                      | Default   |
|-----------------------|----------------------------------|-----------|
| argon2id-time         | Iterations                       | 2         |
| argon2id-memory       | Memory in KB                     | 32768     |
| argon2id-parallelism  | Parallel threads                 | 2         |
| argon2id-hash-length  | Hash length in bytes             | 32        |
| argon2id-salt-length  | Salt length in bytes             | 16        |

---

##TOKEN CONFIGURATION

| Option                    | Description                        | Default     |
|---------------------------|------------------------------------|-------------|
| token-signing-key-file    | RSA or EC PEM private key          | token.pem   |
| token-signing-key-pass    | Key passphrase (if encrypted)      | (optional)  |
| token-expiration          | Access token expiration (seconds)  | 28800       |
| enable-token-revocation   | Supports token revocation          | false       |
| enable-token-refresh      | Enables refresh token support      | false       |
| token-refresh-expiration  | Refresh token TTL (seconds)        | 28800       |

---

##MISC CONFIGURATION

| Option                          | Description                              | Default |
|---------------------------------|------------------------------------------|---------|
| enable-otp-auth                 | Enable OTP-based login                   | false   |
| max-login-failures              | Lockout threshold                        | 5       |
| seconds-to-reset-login-failures | Reset failure counter after X seconds    | 300     |
| failed-password-lockout-duration| Lockout duration (in seconds)            | 300     |

---