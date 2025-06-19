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

---

#### ARGON2ID HASHING CONFIGURATION

| Option                | Description                      | Default   |
|-----------------------|----------------------------------|-----------|
| argon2id-time         | Iterations                       | 2         |
| argon2id-memory       | Memory in KB                     | 32768     |
| argon2id-parallelism  | Parallel threads                 | 2         |
| argon2id-hash-length  | Hash length in bytes             | 32        |
| argon2id-salt-length  | Salt length in bytes             | 16        |

---

#### TOKEN CONFIGURATION

| Option                    | Description                        | Default     |
|---------------------------|------------------------------------|-------------|
| token-signing-key-file    | RSA or EC PEM private key          | token.pem   |
| token-signing-key-pass    | Key passphrase (if encrypted)      | (optional)  |
| token-expiration          | Access token expiration (seconds)  | 28800       |
| enable-token-revocation   | Supports token revocation          | false       |
| enable-token-refresh      | Enables refresh token support      | false       |
| token-refresh-expiration  | Refresh token TTL (seconds)        | 28800       |

---

#### MISC CONFIGURATION

| Option                          | Description                              | Default |
|---------------------------------|------------------------------------------|---------|
| enable-otp-auth                 | Enable OTP-based login                   | false   |
| max-login-failures              | Lockout threshold                        | 5       |
| seconds-to-reset-login-failures | Reset failure counter after X seconds    | 300     |
| failed-password-lockout-duration| Lockout duration (in seconds)            | 300     |