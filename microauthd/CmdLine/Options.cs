using System.CommandLine;

namespace microauthd.CmdLine;

internal static class Options
{
    public static string EnvKeyFor<T>(Option<T> opt, string prefix = "MAD_") =>
        prefix + opt.Name.TrimStart('-').Replace("-", "_").ToUpperInvariant();

    /// <summary>
    /// Represents an option for specifying the path to a configuration file.
    /// </summary>
    /// <remarks>This option requires exactly one argument, which is the file path to the configuration file.
    /// If no value is provided, the default value is <c>"mad.config"</c>.</remarks>
    public static readonly Option<string> ConfigFile =
        new Option<string>("--config", () => "mad.conf", "Path to configuration file")
        {
            Arity = ArgumentArity.ExactlyOne
        };

    /// <summary>
    /// Represents an option to specify a prefix for environment variables.
    /// </summary>
    /// <remarks>The default value for this option is <c>MAD_</c>. This prefix is used to identify environment
    /// variables relevant to the application. The option requires exactly one argument.</remarks>
    public static readonly Option<string> EnvVarPrefix = 
        new Option<string>("--env-var-prefix", () => "MAD_", "Prefix for environment variables (defaults to MAD_)")
        {
            Arity = ArgumentArity.ExactlyOne
        };

    /// <summary>
    /// Represents the database password option for the command-line interface.
    /// </summary>
    /// <remarks>The value for this option can be provided directly or through the environment variable
    /// <c>MAD_DB_PASS</c>. This option requires exactly one argument to be specified.</remarks>
    public static readonly Option<string> DbPass =
        new Option<string>("--db-pass", "Database password (env var MAD_DB_PASS)")
        {
            Arity = ArgumentArity.ExactlyOne
        };

    /// <summary>
    /// Represents an option to disable the use of a database password.
    /// </summary>
    /// <remarks>When this option is enabled, the application will not use a database password.  This can also
    /// be controlled by setting the environment variable <c>MAD_NO_DB_PASS</c> to <c>1</c>.</remarks>
    public static readonly Option<bool> NoDbPass =
        new Option<bool>("--no-db-pass", () => false, "Do not use a database password (env var MAD_NO_DB_PASS = 1)");

    /// <summary>
    /// Represents the option for specifying the path to the database file.
    /// </summary>
    /// <remarks>The default value for this option is "mad.db3". The value can also be set using the 
    /// environment variable <c>MAD_DB_FILE</c>. This option requires exactly one argument.</remarks>
    public static readonly Option<string> DbFile = 
        new Option<string>("--db-file", () => "mad.db3", "Path to the database file (defaults to mad.db3) (env var MAD_DB_FILE)")
        {
            Arity = ArgumentArity.ExactlyOne
        };

    /// <summary>
    /// Represents the option for specifying the IP address to bind the authentication service to.
    /// </summary>
    /// <remarks>The default value is <c>"127.0.0.1"</c>. This option can also be set using the environment
    /// variable <c>MAD_AUTH_IP</c>.</remarks>
    public static readonly Option<string> AuthIp = 
        new Option<string>("--auth-ip", () => "127.0.0.1", "IP address for the authentication service (defaults to 127.0.0.1) (env var MAD_AUTH_IP)")
        {
            Arity = ArgumentArity.ExactlyOne
        };

    /// <summary>
    /// Represents the option for specifying the port used by the authentication service.
    /// </summary>
    /// <remarks>The default value for this option is <see langword="9040"/>.  This value can also be set
    /// using the environment variable <c>MAD_AUTH_PORT</c>.</remarks>
    public static readonly Option<int> AuthPort = 
        new Option<int>("--auth-port", () => 9040, "Port for the authentication service (defaults to 9040) (env var MAD_AUTH_PORT)")
        {
            Arity = ArgumentArity.ExactlyOne
        };

    /// <summary>
    /// Represents the authentication service domain option for the application.
    /// </summary>
    /// <remarks>This option specifies the domain used for the authentication service.  If not explicitly
    /// provided, the default value is <see langword="localhost"/>. The value can also be set using the environment
    /// variable <c>MAD_AUTH_DOMAIN</c>.</remarks>
    public static readonly Option<string> AuthDomain = 
        new Option<string>("--auth-domain", () => "localhost", "Domain for the authentication service (defaults to localhost) (env var MAD_AUTH_DOMAIN)")
        {
            Arity = ArgumentArity.ExactlyOne
        };

    /// <summary>
    /// Represents the option specifying the path to the SSL certificate file for the AUTH service.
    /// </summary>
    /// <remarks>This option is used to configure the SSL certificate file required for secure communication
    /// with the AUTH service.  The value can also be set using the environment variable
    /// <c>MAD_AUTH_SSL_CERT_FILE</c>.</remarks>
    public static readonly Option<string> AuthSSLCertFile = 
        new Option<string>("--auth-ssl-cert-file", "Path to the SSL certificate file for AUTH service (env var MAD_AUTH_SSL_CERT_FILE)")
        {
            Arity = ArgumentArity.ExactlyOne
        };

    /// <summary>
    /// Represents the option for specifying the passphrase of the SSL certificate file used by the AUTH service.
    /// </summary>
    /// <remarks>This option can be set using the command-line argument <c>--auth-ssl-cert-pass</c> or the
    /// environment variable <c>MAD_AUTH_SSL_CERT_PASS</c>.</remarks>
    public static readonly Option<string> AuthSSLCertPass =
        new Option<string>("--auth-ssl-cert-pass", "Passphrase for the SSL certificate file for AUTH service (env var MAD_AUTH_SSL_CERT_PASS)");

    /// <summary>
    /// Represents an option to specify whether HTTP should be used instead of HTTPS for the authentication domain.
    /// </summary>
    /// <remarks>By default, this option is set to <see langword="false"/>, meaning HTTPS is used.  To enable
    /// HTTP, set the environment variable <c>MAD_AUTH_DOMAIN_NO_SSL</c> to <c>1</c>.</remarks>
    public static readonly Option<bool> AuthDomainNoSSL =
        new Option<bool>("--auth-domain-no-ssl", () => false, "Use HTTP instead of HTTPS for external AUTH domain links (defaults to false) (env var MAD_AUTH_DOMAIN_NO_SSL = 1)");

    /// <summary>
    /// Represents the option for specifying the IP address to bind the admin service to.
    /// </summary>
    /// <remarks>The default value for this option is <c>"127.0.0.1"</c>. This value can also be set using the
    /// environment variable <c>MAD_ADMIN_IP</c>. The option requires exactly one argument to be provided.</remarks>
    public static readonly Option<string> AdminIp =
        new Option<string>("--admin-ip", () => "127.0.0.1", "IP address for the admin service (defaults to 127.0.0.1) (env var MAD_ADMIN_IP)")
        {
            Arity = ArgumentArity.ExactlyOne
        };

    /// <summary>
    /// Represents the option for specifying the port used by the admin service.
    /// </summary>
    /// <remarks>The default value for this option is <see langword="9041"/>. This value can also be set using
    /// the  environment variable <c>MAD_ADMIN_PORT</c>. The option requires exactly one argument to be
    /// provided.</remarks>
    public static readonly Option<int> AdminPort =
        new Option<int>("--admin-port", () => 9041, "Port for the admin service (defaults to 9041) (env var MAD_ADMIN_PORT)")
        {
            Arity = ArgumentArity.ExactlyOne
        };

    /// <summary>
    /// Represents the option for specifying the domain of the admin service.
    /// </summary>
    /// <remarks>The default value for this option is <see langword="localhost"/>.  This value can also be set
    /// using the environment variable <c>MAD_ADMIN_DOMAIN</c>.</remarks>
    public static readonly Option<string> AdminDomain = 
        new Option<string>("--admin-domain", () => "localhost", "Domain for the admin service (defaults to localhost) (env var MAD_ADMIN_DOMAIN)")
        {
            Arity = ArgumentArity.ExactlyOne
        };

    /// <summary>
    /// Represents the option for specifying the path to the SSL certificate file used by the ADMIN service.
    /// </summary>
    /// <remarks>This option is required and must be provided exactly once. The value can also be set using
    /// the  environment variable <c>MAD_ADMIN_SSL_CERT_FILE</c>.</remarks>
    public static readonly Option<string> AdminSSLCertFile =
        new Option<string>("--admin-ssl-cert-file", "Path to the SSL certificate file for ADMIN service (env var MAD_ADMIN_SSL_CERT_FILE)")
        {
            Arity = ArgumentArity.ExactlyOne
        };

    /// <summary>
    /// Represents an option for specifying the passphrase of the SSL certificate file used by the ADMIN service.
    /// </summary>
    /// <remarks>This option can be set using the command-line argument <c>--admin-ssl-cert-pass</c> or the
    /// environment variable <c>MAD_ADMIN_SSL_CERT_PASS</c>. It is typically required when the ADMIN service is
    /// configured to use SSL and the certificate file is password-protected.</remarks>
    public static readonly Option<string> AdminSSLCertPass =
        new Option<string>("--admin-ssl-cert-pass", "Passphrase for the SSL certificate file for ADMIN service (env var MAD_ADMIN_SSL_CERT_PASS)");

    /// <summary>
    /// Represents an option to specify whether HTTP should be used instead of HTTPS for the admin domain.
    /// </summary>
    /// <remarks>This option defaults to <see langword="false"/>. When enabled, HTTP will be used instead of
    /// HTTPS for the admin domain. The value can also be set using the environment variable
    /// <c>MAD_ADMIN_DOMAIN_NO_SSL</c> with a value of <c>1</c>.</remarks>
    public static readonly Option<bool> AdminDomainNoSSL =
        new Option<bool>("--admin-domain-no-ssl", () => false, "Use HTTP instead of HTTPS for the external admin domain (defaults to false) (env var MAD_ADMIN_DOMAIN_NO_SSL = 1)");

    /// <summary>
    /// Represents the time cost parameter for Argon2id hashing.
    /// </summary>
    /// <remarks>This option specifies the number of iterations (time cost) used in the Argon2id hashing
    /// algorithm.  The default value is 2. The value can also be set using the environment variable
    /// <c>MAD_ARGON2_TIME</c>.</remarks>
    public static readonly Option<int> Argon2idTime =
        new Option<int>("--argon2id-time", () => 2, "Time cost for Argon2id hashing (defaults to 2) (env var MAD_ARGON2_TIME)")
        {
            Arity = ArgumentArity.ExactlyOne
        };

    /// <summary>
    /// Represents the memory cost, in kilobytes, for Argon2id hashing.
    /// </summary>
    /// <remarks>This option specifies the memory cost parameter for the Argon2id hashing algorithm.  The
    /// default value is 32,768 KB. The value can be set via the command-line argument  <c>--argon2id-memory</c> or the
    /// environment variable <c>MAD_ARGON2_MEM</c>.</remarks>
    public static readonly Option<int> Argon2idMemory =
        new Option<int>("--argon2id-memory", () => 32768, "Memory cost for Argon2id hashing in KB (defaults to 32768) (env var MAD_ARGON2_MEM)")
        {
            Arity = ArgumentArity.ExactlyOne
        };

    /// <summary>
    /// Represents the parallelism factor for Argon2id hashing.
    /// </summary>
    /// <remarks>This option specifies the degree of parallelism to use during Argon2id hashing.  The default
    /// value is <see langword="2"/>. The value can also be set using the  environment variable
    /// <c>MAD_ARGON2_PARALLEL</c>.</remarks>
    public static readonly Option<int> Argon2idParallelism =
        new Option<int>("--argon2id-parallelism", () => 2, "Parallelism factor for Argon2id hashing (defaults to 2) (env var MAD_ARGON2_PARALLEL)")
        {
            Arity = ArgumentArity.ExactlyOne
        };

    /// <summary>
    /// Represents the option to specify the length of the hash output for Argon2id.
    /// </summary>
    /// <remarks>The default value is 32. This option corresponds to the environment variable 
    /// <c>MAD_ARGON2_HASH_LENGTH</c>. The value must be explicitly provided as an argument  or will default to the
    /// specified value.</remarks>
    public static readonly Option<int> Argon2idHashLength =
        new Option<int>("--argon2id-hash-length", () => 32, "Length of the hash output for Argon2id (defaults to 32) (env var MAD_ARGON2_HASH_LENGTH)")
        {
            Arity = ArgumentArity.ExactlyOne
        };

    /// <summary>
    /// Represents the option to specify the length of the salt for the Argon2id hashing algorithm.
    /// </summary>
    /// <remarks>The default value for this option is 16. This value can be overridden by providing a specific
    /// value through the command-line argument <c>--argon2id-salt-length</c> or by setting the environment variable
    /// <c>MAD_ARGON2_SALT_LENGTH</c>.</remarks>
    public static readonly Option<int> Argon2idSaltLength =
        new Option<int>("--argon2id-salt-length", () => 16, "Length of the salt for Argon2id (defaults to 16) (env var MAD_ARGON2_SALT_LENGTH)")
        {
            Arity = ArgumentArity.ExactlyOne
        };

    /// <summary>
    /// Represents the option for specifying the path to the .PEM file containing the token signing key.
    /// </summary>
    /// <remarks>This option is used to provide the file path to the token signing key in .PEM format.  If not
    /// specified, the default value is <c>token.pem</c>. The value can also be set using the  environment variable
    /// <c>MAD_TOKEN_SIGNING_KEY_FILE</c>.</remarks>
    public static readonly Option<string> TokenSigningKeyFile = 
        new Option<string>("--token-signing-key-file", () => "token.pem", "Path to the .PEM file containing the token signing key (defaults to token.pem) (env var MAD_TOKEN_SIGNING_KEY_FILE)")
        {
            Arity = ArgumentArity.ExactlyOne
        };

    /// <summary>
    /// Represents an option to prefer using an EC-based token signing key instead of RSA.
    /// </summary>
    /// <remarks>This option defaults to <see langword="false"/> and can be overridden by setting the
    /// environment variable  <c>MAD_PREFER_EC_TOKEN_SIGNER</c> to <c>1</c>. Use this option to specify whether EC-based
    /// token signing keys  should be prioritized over RSA-based keys.</remarks>
    public static readonly Option<bool> PreferECDSASigningKey =
        new Option<bool>("--prefer-ec-token-signer", () => false, "Prefer using an EC-based token signing key instead of RSA (defaults to false) (env var MAD_PREFER_EC_TOKEN_SIGNER = 1)");

    /// <summary>
    /// Represents the length of the RSA token signing key in bits.
    /// </summary>
    /// <remarks>The default value is 2048 bits. This option can be configured using the environment variable 
    /// <c>MAD_TOKEN_SIGNING_KEY_LENGTH_RSA</c>.</remarks>
    public static readonly Option<int> TokenSigningKeyLengthRSA =
        new Option<int>("--token-signing-key-length-rsa", () => 2048, "Length of the RSA token signing key in bits (defaults to 2048) (env var MAD_TOKEN_SIGNING_KEY_LENGTH_RSA)")
        {
            Arity = ArgumentArity.ExactlyOne
        };

    /// <summary>
    /// Represents the option for specifying the path to the .PEM file containing the admin token signing key.
    /// </summary>
    /// <remarks>This option defaults to "admin_token.pem" if no value is provided. The value can also be set
    /// using the environment variable <c>MAD_ADMIN_TOKEN_SIGNING_KEY_FILE</c>.</remarks>
    public static readonly Option<string> AdminTokenSigningKeyFile =
        new Option<string>("--admin-token-signing-key-file", () => "admin_token.pem", "Path to the .PEM file containing the admin token signing key (defaults to admin_token.pem) (env var MAD_ADMIN_TOKEN_SIGNING_KEY_FILE)")
        {
            Arity = ArgumentArity.ExactlyOne
        };

    /// <summary>
    /// Represents an option to prefer using an EC-based admin token signing key instead of RSA.
    /// </summary>
    /// <remarks>This option defaults to <see langword="false"/>. When enabled, the system will prioritize 
    /// EC-based keys for signing admin tokens. The behavior can also be controlled via the  environment variable
    /// <c>MAD_PREFER_EC_ADMIN_TOKEN_SIGNER</c>, which should be set to <c>1</c>  to enable this preference.</remarks>
    public static readonly Option<bool> PreferECDSAAdminSigningKey =
        new Option<bool>("--prefer-ec-admin-token-signer", () => false, "Prefer using an EC-based admin token signing key instead of RSA (defaults to false) (env var MAD_PREFER_EC_ADMIN_TOKEN_SIGNER = 1)");

    /// <summary>
    /// Represents the length of the RSA admin token signing key in bits.
    /// </summary>
    /// <remarks>The default value is 2048 bits. This option can be configured using the environment variable 
    /// <c>MAD_ADMIN_TOKEN_SIGNING_KEY_LENGTH_RSA</c>.</remarks>
    public static readonly Option<int> AdminTokenSigningKeyLengthRSA =
        new Option<int>("--admin-token-signing-key-length-rsa", () => 2048, "Length of the RSA admin token signing key in bits (defaults to 2048) (env var MAD_ADMIN_TOKEN_SIGNING_KEY_LENGTH_RSA)")
        {
            Arity = ArgumentArity.ExactlyOne
        };

    /// <summary>
    /// Represents an option for specifying the passphrase used to secure the token signing key.
    /// </summary>
    /// <remarks>This option requires exactly one argument and can be set using the command-line argument 
    /// --token-signing-key-passphrase or the environment variable MAD_TOKEN_SIGNING_KEY_PASS.</remarks>
    public static readonly Option<string> TokenSigningKeyPassphrase =
        new Option<string>("--token-signing-key-pass", "Passphrase for the token signing key (env var MAD_TOKEN_SIGNING_KEY_PASS)")
        {
            Arity = ArgumentArity.ExactlyOne
        };

    /// <summary>
    /// Represents the passphrase for the admin token signing key.
    /// </summary>
    /// <remarks>This option is used to specify the passphrase required for the admin token signing key.  The
    /// value can also be provided via the environment variable <c>MAD_ADMIN_TOKEN_SIGNING_KEY_PASS</c>.</remarks>
    public static readonly Option<string> AdminTokenSigningKeyPassphrase = 
        new Option<string>("--admin-token-signing-key-pass", "Passphrase for the admin token signing key (env var MAD_ADMIN_TOKEN_SIGNING_KEY_PASS)")
        {
            Arity = ArgumentArity.ExactlyOne
        };

    /// <summary>
    /// Represents the option for specifying the token expiration time in seconds.
    /// </summary>
    /// <remarks>The default value is 3600 seconds (1 hour). This value can be overridden by providing the
    /// <c>--token-expiration-time</c> argument or by setting the <c>MAD_TOKEN_EXPIRATION_TIME</c> environment
    /// variable.</remarks>
    public static readonly Option<int> TokenExpirationTime =
        new Option<int>("--token-expiration", () => 3600, "Expiration time for tokens in seconds (defaults to 3600 (1hr)) (env var MAD_TOKEN_EXPIRATION)")
        {
            Arity = ArgumentArity.ExactlyOne
        };

    /// <summary>
    /// Represents an option specifying the number of days after token expiration to purge tokens.
    /// </summary>
    /// <remarks>The default value is 7 days. This option can be configured using the environment variable 
    /// <c>MAD_TOKEN_PURGE_DAYS</c>.</remarks>
    public static readonly Option<int> TokenPurgeDays =
        new Option<int>("--token-purge-days", () => 7, "Number of days after expiration to purge tokens (defaults to 7 days) (env var MAD_TOKEN_PURGE_DAYS)")
        {
            Arity = ArgumentArity.ExactlyOne
        };

    /// <summary>
    /// Represents the expiration time for admin tokens, in seconds.
    /// </summary>
    /// <remarks>The default value is 3600 seconds (1 hour). This option can be configured using the 
    /// environment variable <c>MAD_ADMIN_TOKEN_EXPIRATION</c>.</remarks>
    public static readonly Option<int> AdminTokenExpirationTime =
        new Option<int>("--admin-token-expiration", () => 3600, "Expiration time for admin tokens in seconds (defaults to 3600 (1hr)) (env var MAD_ADMIN_TOKEN_EXPIRATION)")
        {
            Arity = ArgumentArity.ExactlyOne
        };

    /// <summary>
    /// Represents an option to enable or disable token revocation.
    /// </summary>
    /// <remarks>This option defaults to <see langword="false"/> and can be configured by setting the environment
    /// variable <c>MAD_ENABLE_TOKEN_REVOCATION</c> to <c>1</c>. The option requires an explicit value to be provided.</remarks>
    public static readonly Option<bool> EnableTokenRevocation = 
        new Option<bool>("--enable-token-revocation", () => true, "Enable token revocation (defaults to false) (env var MAD_ENABLE_TOKEN_REVOCATION = 1)");

    /// <summary>
    /// Represents an option to enable or disable token refresh functionality.
    /// </summary>
    /// <remarks>This option defaults to <see langword="false"/> and can be configured by setting the environment
    /// variable <c>MAD_ENABLE_TOKEN_REFRESH</c> to <c>1</c>. The option requires an explicit value to be provided.</remarks>
    public static readonly Option<bool> EnableTokenRefresh =
        new Option<bool>("--enable-token-refresh", () => false, "Enable token refresh (defaults to false) (env var MAD_ENABLE_TOKEN_REFRESH = 1)");

    /// <summary>
    /// Represents the expiration time for refresh tokens, in seconds.
    /// </summary>
    /// <remarks>The default value is 259,200 seconds (3 days). This value can be configured using the 
    /// environment variable <c>MAD_TOKEN_REFRESH_TIME</c>.</remarks>
    public static readonly Option<int> RefreshTokenExpiration =
        new Option<int>("--refresh-token-expiration", () => 259200, "Expiration time for refresh tokens in seconds (defaults to 259200 (3 days)) (env var MAD_TOKEN_REFRESH_EXPIRATION)")
        {
            Arity = ArgumentArity.ExactlyOne
        };

    /// <summary>
    /// Represents an option specifying the number of days after expiration to purge refresh tokens.
    /// </summary>
    /// <remarks>The default value is 7 days. This option can be configured using the environment variable 
    /// <c>MAD_REFRESH_TOKEN_PURGE_DAYS</c>.</remarks>
    public static readonly Option<int> RefreshTokenPurgeDays =
        new Option<int>("--refresh-token-purge-days", () => 7, "Number of days after expiration to purge refresh tokens (defaults to 7 days) (env var MAD_REFRESH_TOKEN_PURGE_DAYS)")
        {
            Arity = ArgumentArity.ExactlyOne
        };

    /// <summary>
    /// Represents an option to print the effective configuration.
    /// </summary>
    /// <remarks>This option is a boolean flag that determines whether the effective configuration should be
    /// printed.</remarks>
    public static readonly Option<bool> PrintEffectiveConfig = 
        new Option<bool>("--print-effective-config", () => false, "Print the effective configuration and exit");

    /// <summary>
    /// Represents the maximum number of login failures allowed before an account is locked.
    /// </summary>
    /// <remarks>The default value is 5. This option can be configured via the command-line argument 
    /// <c>--max-login-failures</c> or the environment variable <c>MAD_MAX_LOGIN_FAILURES</c>.</remarks>
    public static readonly Option<int> MaxLoginFailures = 
        new Option<int>("--max-login-failures", () => 5, "Maximum number of login failures before account lockout (defaults to 5) (env var MAD_MAX_LOGIN_FAILURES)")
        {
            Arity = ArgumentArity.ExactlyOne
        };

    /// <summary>
    /// Represents the number of seconds after which login failure counts are reset.
    /// </summary>
    /// <remarks>This option defaults to 300 seconds (5 minutes) and can be configured via the  environment
    /// variable <c>MAD_SECONDS_TO_RESET_LOGIN_FAILURES</c>.</remarks>
    public static readonly Option<int> SecondsToResetLoginFailures =
        new Option<int>("--seconds-to-reset-login-failures", () => 300, "Seconds to reset login failures (defaults to 300) (env var MAD_SECONDS_TO_RESET_LOGIN_FAILURES)")
        {
            Arity = ArgumentArity.ExactlyOne
        };

    /// <summary>
    /// Represents the duration, in seconds, for which an account is locked after reaching the maximum number of failed
    /// login attempts.
    /// </summary>
    /// <remarks>The default value is 300 seconds. This value can be configured via the environment variable
    /// <c>MAD_FAILED_PASSWORD_LOCKOUT_DURATION</c>.</remarks>
    public static readonly Option<int> FailedPasswordLockoutDuration = 
        new Option<int>("--failed-password-lockout-duration", () => 300, "Duration in seconds for which an account is locked after maximum login failures (defaults to 300) (env var MAD_FAILED_PASSWORD_LOCKOUT_DURATION)")
        {
            Arity = ArgumentArity.ExactlyOne
        };

    /// <summary>
    /// Represents an option for specifying the path to the log file.
    /// </summary>
    /// <remarks>The default value for this option is <c>microauthd.log</c>. The value can also be set using
    /// the  environment variable <c>MAD_LOG_FILE</c>. This option requires exactly one argument to be
    /// provided.</remarks>
    public static readonly Option<string> LogFile =
        new Option<string>("--log-file", () => "microauthd.log", "Path to the log file (defaults to microauthd.log) (env var MAD_LOG_FILE)")
        {
            Arity = ArgumentArity.ExactlyOne
        };

    /// <summary>
    /// Represents an option to enable or disable audit logging.
    /// </summary>
    /// <remarks>This option defaults to <see langword="false"/> if not explicitly set.  It can be configured
    /// via the environment variable <c>MAD_ENABLE_AUDIT_LOGGING</c> by setting its value to <c>1</c>.</remarks>
    public static readonly Option<bool> EnableAuditLogging =
        new Option<bool>("--enable-audit-logging", () => false, "Enable audit logging (defaults to false) (env var MAD_ENABLE_AUDIT_LOGGING = 1)");

    /// <summary>
    /// Represents an option specifying the number of days to retain audit log entries.
    /// </summary>
    /// <remarks>The default value is 30 days. This option can be configured using the environment variable
    /// <c>MAD_DAYS_TO_KEEP_AUDIT_LOG_ENTRIES</c>.</remarks>
    public static readonly Option<int> AuditLogRetentionDays =
        new Option<int>("--audit-log-retention-days", () => 30, "Number of days to keep audit log entries (defaults to 30) (env var MAD_AUDIT_LOG_RETENTION_DAYS)")
        {
            Arity = ArgumentArity.ExactlyOne
        };

    /// <summary>
    /// Represents the issuer URL for OIDC authentication.
    /// </summary>
    /// <remarks>This option specifies the OpenID Connect (OIDC) issuer.  The value can also be set
    /// using the environment variable <c>MAD_OIDC_ISSUER</c>.</remarks>
    public static readonly Option<string> OidcIssuer = 
        new Option<string>("--oidc-issuer", () => "microauthd", "Issuer for OIDC authentication (defaults to 'microauthd') (env var MAD_OIDC_ISSUER)")
        {
            Arity = ArgumentArity.ExactlyOne
        };
    
    /// <summary>
    /// Represents the client ID used for OIDC authentication.
    /// </summary>
    /// <remarks>This option is configured using the command-line argument <c>--oidc-client-id</c> or the
    /// environment variable <c>MAD_OIDC_CLIENT_ID</c>. The value must be explicitly provided as the option requires
    /// exactly one argument.</remarks>
    public static readonly Option<string> OidcClientId = 
        new Option<string>("--oidc-client-id", () => "app", "Client ID for OIDC authentication (defaults to 'app') (env var MAD_OIDC_CLIENT_ID)")
        {
            Arity = ArgumentArity.ExactlyOne
        };

    /// <summary>
    /// Represents the client secret used for OIDC authentication.
    /// </summary>
    /// <remarks>This option is configured using the <c>--oidc-client-secret</c> command-line argument or the 
    /// environment variable <c>MAD_OIDC_CLIENT_SECRET</c>. The value must be explicitly provided  as the option
    /// requires exactly one argument.</remarks>
    public static readonly Option<string> OidcClientSecret =
        new Option<string>("--oidc-client-secret", "Client secret for OIDC authentication (env var MAD_OIDC_CLIENT_SECRET)")
        {
            Arity = ArgumentArity.ExactlyOne
        };
        
    /// <summary>
    /// Represents an option to enable the Swagger UI for the authentication service.
    /// </summary>
    /// <remarks>This option is disabled by default. To enable it, set the value to <see langword="true"/>  or
    /// use the environment variable <c>MAD_ENABLE_AUTH_SWAGGER</c> with a value of <c>1</c>.</remarks>
    public static readonly Option<bool> EnableAuthSwagger = 
        new Option<bool>("--enable-auth-swagger", () => false, "Enable Swagger UI for the authentication service (defaults to false) (env var MAD_ENABLE_AUTH_SWAGGER = 1)");

    /// <summary>
    /// Represents an option to enable or disable the Swagger UI for the admin service.
    /// </summary>
    /// <remarks>By default, this option is disabled. To enable it, set the value to <see langword="true"/> 
    /// or use the environment variable <c>MAD_ENABLE_ADMIN_SWAGGER</c> with a value of <c>1</c>.</remarks>
    public static readonly Option<bool> EnableAdminSwagger =
        new Option<bool>("--enable-admin-swagger", () => false, "Enable Swagger UI for the admin service (defaults to false) (env var MAD_ENABLE_ADMIN_SWAGGER = 1)");

    /// <summary>
    /// Represents a configuration option for specifying a list of trusted proxy IP addresses.
    /// </summary>
    /// <remarks>This option is used to define a comma-separated list of IP addresses that are trusted in the 
    /// X-Forwarded-For header. It can be configured via the environment variable <c>MAD_TRUSTED_PROXIES</c>. Multiple
    /// arguments can be provided per token.</remarks>
    public static readonly Option<List<string>> TrustedProxies =
        new Option<List<string>>(name: "--trusted-proxies", description: "Comma-separated list of IP addresses to trust in X-Forwarded-For (env var MAD_TRUSTED_PROXIES)")
    {
        AllowMultipleArgumentsPerToken = true
    };

    /// <summary>
    /// Represents an option to enable or disable PKCE (Proof Key for Code Exchange) support.
    /// </summary>
    /// <remarks>PKCE is a security feature used in OAuth 2.0 authorization flows to mitigate certain attack
    /// vectors. By default, this option is enabled (<see langword="true"/>). The value can be overridden using the
    /// environment variable <c>MAD_ENABLE_PKCE</c> set to <c>1</c>.</remarks>
    public static readonly Option<bool> EnablePkce = 
        new Option<bool>("--enable-pkce", () => true, "Enable PKCE (Proof Key for Code Exchange) support (defaults to true) (env var MAD_ENABLE_PKCE = 1)");

    /// <summary>
    /// Represents the PKCE code lifetime option, specifying the duration in seconds for which a PKCE code remains
    /// valid.
    /// </summary>
    /// <remarks>The default value for this option is 120 seconds. This option can be configured via the
    /// environment variable  <c>MAD_PKCE_CODE_LIFETIME</c>. The option requires exactly one argument to be
    /// provided.</remarks>
    public static readonly Option<int> PkceCodeLifetime = 
        new Option<int>("--pkce-code-lifetime", () => 120, "PKCE code lifetime in seconds (defaults to 120) (env var MAD_PKCE_CODE_LIFETIME)")
        {
            Arity = ArgumentArity.ExactlyOne
        };

    /// <summary>
    /// Represents an option to enable or disable serving public files for the authentication service.
    /// </summary>
    /// <remarks>This option defaults to <see langword="false"/> and can be overridden by setting the
    /// environment variable  <c>MAD_SERVE_PUBLIC_AUTH_FILES</c> to <c>1</c>. Use this option to control whether public
    /// authentication-related  files are served by the application.</remarks>
    public static readonly Option<bool> ServePublicAuthFiles =
        new Option<bool>("--serve-public-auth-files", () => false, "Serve public files for the authentication service (defaults to false) (env var MAD_SERVE_PUBLIC_AUTH_FILES = 1)");

    /// <summary>
    /// Represents an option to enable or disable password caching.
    /// </summary>
    /// <remarks>The default value for this option is <see langword="true"/>.  Password caching can be
    /// controlled via the environment variable <c>MAD_ENABLE_PASS_CACHE</c>,  which should be set to <c>1</c> to enable
    /// caching.</remarks>
    public static readonly Option<bool> EnablePassCache =
        new Option<bool>("--enable-pass-cache", () => true, "Enable password caching (defaults to true) (env var MAD_ENABLE_PASS_CACHE = 1)");
        
    /// <summary>
    /// Represents the duration, in seconds, for which passwords are cached.
    /// </summary>
    /// <remarks>The default value is 300 seconds. This option can be configured using the environment
    /// variable  <c>MAD_PASS_CACHE_DURATION</c>.</remarks>
    public static readonly Option<int> PassCacheDuration =
        new Option<int>("--pass-cache-duration", () => 300, "Duration in seconds for which passwords are cached (defaults to 300) (env var MAD_PASS_CACHE_DURATION)")
        {
            Arity = ArgumentArity.ExactlyOne
        };

    /// <summary>
    /// Represents an option to enable or disable Docker mode.
    /// </summary>
    /// <remarks>When enabled, the application runs in Docker mode. The default value is <see
    /// langword="false"/>. This option can also be configured using the environment variable <c>MAD_DOCKER</c>, which
    /// should be set to <c>1</c> to enable Docker mode.</remarks>
    public static readonly Option<bool> Docker =
        new Option<bool>("--docker", () => false, "Run in Docker mode (defaults to false) (env var MAD_DOCKER = 1)");
}
