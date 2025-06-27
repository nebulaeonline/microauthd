# microauthd
---
## Configuration Mechanism
---

### Introduction

microauthd tries to be as flexible as possible with its configuration options. Options are consistent across the three ways of setting them. The first place is the configuration file (`mad.conf` by default). The configuration file is just a simple .ini style file with `key = value` pairs. 

Values can also be set via environment variables for installations that prefer that method. The names of the environment variables are exactly the same as the options in the configuration file, only uppercased and with underscores `_` instead of dashes, and prefixed by default `MAD_` (the prefix is overridable in the config file or on the command line) an example would be `MAD_DB_FILE` or `MAD_DB_PASS`. Variables that are feature flags will accept being set to 1 or true.

Values can also be set on the command line, and these mirror the configuration file verbatim- so `--db-file=xxx.db3` or `--db-pass=1234`.

The order of precedence from least to greatest is config file -> environment variable -> command line switch. So environment variables override the config file, and command line switches override both the config file and any environment variables.

---

#### DATABASE CONFIGURATION

| Option      | Description                          | Default     |
|-------------|--------------------------------------|-------------|
| db-file     | SQLite or SQLCipher database path    | mad.db3     |
| db-pass     | Password for the database            | (required unless `no-db-pass`) |
| no-db-pass  | Disable DB encryption                | false       |

As an extra security measure, if you do not want a password, you must not set one firstly, and secondly you need to specify --no-db-pass. This is done to prevent accidental failure to assign a password to your users database.

---

#### AUTHENTICATION SERVER CONFIGURATION

| Option         | Description                        | Default       |
|----------------|------------------------------------|---------------|
| auth-ip        | Listening IP                       | 127.0.0.1     |
| auth-port      | Listening port                     | 9040          |
| auth-domain    | Expected domain                    | localhost     |
| auth-use-ssl   | Use TLS (standalone)               | false         |
| auth-ssl-cert  | SSL certificate path               | auth.pem      |
| auth-ssl-pass  | SSL private key passphrase         | (optional)    |
| auth-domain-no-ssl | SSL on external domain?        | false (yes to SSL) |

It should go without saying that best practices are to put microauthd behind a reverse proxy such as nginx or caddy that handles TLS termination, and to set the trusted proxy (or proxies) via the optoin described below. If that is not possible, you should supply an SSL cert so that kestrel (the webserver within microauthd) can terminate TLS itself. DO NOT run an auth system on the open internet using only HTTP.

---

#### ADMINISTRATION SERVER CONFIGURATION

| Option         | Description                        | Default       |
|----------------|------------------------------------|---------------|
| admin-ip       | Listening IP                       | 127.0.0.1     |
| admin-port     | Listening port                     | 9041          |
| admin-domain   | Expected domain                    | localhost     |
| admin-use-ssl  | Use TLS (standalone)               | false         |
| admin-ssl-cert | SSL certificate path               | admin.pem     |
| admin-ssl-pass | SSL private key passphrase         | (optional)    |
| admin-domain-no-ssl | SSL on external domain?       | false (yes to SSL) |

It is recommended to host the admin side on a completely locked down domain and port. If you can get away with only granting specific IPs access on the public side, it is highly recommended. Different IP, different domain, different port from AUTH. The ADMIN has many powerful endpoints, and keeping them protected and private is good hygiene.

---

#### ARGON2ID HASHING CONFIGURATION

| Option                | Description                      | Default   |
|-----------------------|----------------------------------|-----------|
| argon2id-time         | Iterations                       | 2         |
| argon2id-memory       | Memory in KB                     | 32768     |
| argon2id-parallelism  | Parallel threads                 | 2         |
| argon2id-hash-length  | Hash length in bytes             | 32        |
| argon2id-salt-length  | Salt length in bytes             | 16        |

Current (June 2025) OWASP Recommendations: 19MB Memory, 2 Iterations, 2 Parallel Threads, 32-byte hash length, minimum 16 byte salt.

---

#### TOKEN CONFIGURATION

| Option                    | Description                        | Default     |
|---------------------------|------------------------------------|-------------|
| token-signing-key-file    | RSA or EC PEM private key          | token.pem   |
| prefer-ec-token-signer    | Use EC PEM private key (not RSA)   | false       |
| token-signing-key-length  | RSA Key Length (when using RSA)    | 2048        |
| token-signing-key-pass    | Key passphrase (if encrypted)      | (optional)  |
| token-expiration          | Access token expiration (seconds)  | 28800       |
| enable-token-revocation   | Supports token revocation          | false       |
| enable-token-refresh      | Enables refresh token support      | false       |
| token-refresh-expiration  | Refresh token TTL (seconds)        | 28800       |

You may use RSA or ECDSA (elliptic curve) certificates with microauthd. You can even mix & match between ADMIN & AUTH. Be warned, however, that microauthd will NOT regenerate signing certificates if you make a change. In order to regenerate certificates, delete the private & publc key files for the cert you want to regenerate and restart microauthd. It will then (and only then) regenerate certificates in the manner specified.

---

#### AUTH TOKEN CONFIGURATION

| Option                          | Description                        | Default     |
|---------------------------------|------------------------------------|-------------|
| admin-token-signing-key-file    | RSA or EC PEM private key          | token.pem   |
| prefer-ec-admin-token-signer    | Use EC PEM private key (not RSA)   | false       |
| admin-token-signing-key-length  | RSA Key Length (when using RSA)    | 2048        |
| admin-token-signing-key-pass    | Key passphrase (if encrypted)      | (optional)  |
| admin-token-expiration          | Access token expiration (seconds)  | 28800       |

---

#### OIDC CONFIGURATION

| Option                          | Description                        | Default     |
|---------------------------------|------------------------------------|-------------|
| oidc-issuer                     | The OIDC "Authority" Issuing the tokens; Should be FQDN (e.g. https://auth.example.com)                                   | none        |

Note: you will be prompted to create an initial OIDC client during OOBE; each client has their own client id and client secret (for multiple auth pathways or apps), but the oidc issuer is only set once for the server.

---

#### Swagger config

| Option                          | Description                        | Default     |
|---------------------------------|------------------------------------|-------------|
| enable-auth-swagger             | Enables swagger endpoint on AUTH port | false    |
| enable-admin-swagger             | Enables swagger endpoint on ADMIN port | false    |

Swagger is set up for API discovery on both endpoints, but is disabled by default. It is not recommended to run in production with Swagger enabled.

---

#### PKCE CONFIGURATION

| Option                          | Description                        | Default     |
|---------------------------------|------------------------------------|-------------|
| enable-pkce                     | Enables PKCE challenge-response support | true    |
| pkce-code-lifetime              | Specifies how long (in seconds) the PKCE codes will be honored for after they are issued | 120 seconds   |

---

#### MISC CONFIGURATION

| Option                          | Description                              | Default |
|---------------------------------|------------------------------------------|---------|
| enable-otp-auth                 | Enable OTP-based login                   | false   |
| max-login-failures              | Lockout threshold                        | 5       |
| seconds-to-reset-login-failures | Reset failure counter after X seconds    | 300     |
| failed-password-lockout-duration| Lockout duration (in seconds)            | 300     |
| serve-public-auth-files         | Serve files located in /public via AUTH  | false   |
| trusted-proxies                 | Comma separated list of trusted proxies; when set, microauthd will look for X-Forwarded-For and X-Forwarded-Proto               | blank   |