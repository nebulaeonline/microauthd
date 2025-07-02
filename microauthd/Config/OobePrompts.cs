namespace microauthd.Config;

using microauthd.Common;
using microauthd.Services;

internal static class OobePrompts
{
    public static void PrintIntro()
    {
        Console.WriteLine("Welcome to microauthd!");
        Console.WriteLine("=======================\n");

        Console.WriteLine("It looks like this is your first time running microauthd (or your database is missing).\nLet's walk through a few defaults and setup steps.\n");

        Console.WriteLine("microauthd uses its working directory for all files by default — including:");
        Console.WriteLine("- the config file");
        Console.WriteLine("- the SQLite database");
        Console.WriteLine("- log files");
        Console.WriteLine("- token signing keys");
        Console.WriteLine("These defaults can be overridden via command-line arguments, environment variables, or a config file.");
        Console.WriteLine("Precedence is: CLI arguments > environment variables > config file > defaults.\n");

        Console.WriteLine("The config file is optional (INI-style), but highly recommended for sensitive secrets.");
        Console.WriteLine("Warning: CLI arguments may be visible to other users via 'ps' or 'top'.");
        Console.WriteLine("Warning: Environment variables may be inherited by child processes.");
        Console.WriteLine("It's best practice to run microauthd under its own user and use chmod 600 on config/db files.\n");

        Console.WriteLine("Example:");
        Console.WriteLine("--------");
        Console.WriteLine("At startup, microauthd looks for a config file in this order:");
        Console.WriteLine("1. --config CLI option");
        Console.WriteLine("2. Environment variable MAD_CONFIG (or [PREFIX]_CONFIG if using --env-var-prefix)");
        Console.WriteLine("3. Fallback to 'mad.conf' in the current working directory.\n");

        Console.WriteLine("Even without a config file, microauthd will continue using built-in defaults or any CLI/env values.");
        Console.WriteLine("This flexibility lets you run multiple instances however you prefer —");
        Console.WriteLine("we don’t assume anything like /etc or system-level conventions. You may even be on Windows or macOS.\n");

        Console.WriteLine("You must specify a database file and password, and create an admin user account. You will be given the");
        Console.WriteLine("option to do a guided setup to create your configuration file, but it is not required.\n");

        Console.WriteLine("Please follow the prompts to configure your instance.\n");
    }


    public static void AskFullSetup(OobeState state)
    {
        Console.Write("Do you want to do a full guided setup? (y/n): ");
        var input = Console.ReadLine()?.Trim().ToLowerInvariant();
        while (input != "y" && input != "yes" && input != "n" && input != "no")
        {
            Console.Write("Please enter y or n: ");
            input = Console.ReadLine()?.Trim().ToLowerInvariant();
        }
        state.FullSetup = (input == "y" || input == "yes");
    }

    public static void PromptDbPathAndPassword(OobeState state)
    {
        state.DbFilePath = Prompt("Please enter the full path to your desired database file", state.Config.DbFile);

        Console.Write("Please enter a password for your database file (leave blank for none): ");
        var input = Utils.ReadHiddenInput();

        if (string.IsNullOrWhiteSpace(input))
        {
            Console.Write("Are you sure you want to leave the database password empty? (y/n): ");
            var confirm = Console.ReadLine()?.Trim().ToLowerInvariant();
            if (confirm == "y" || confirm == "yes")
                state.DbPass = string.Empty;
            else
                PromptDbPathAndPassword(state); // restart if declined
        }
        else
        {
            state.DbPass = input;
        }
    }

    public static void PromptConfigPaths(OobeState state)
    {
        state.WriteEnvFile = PromptYesNo("Do you want to write a .env file with environment variables? (A minimal config file will still be generated.)");

        if (state.WriteEnvFile)
        {
            state.EnvFilePath = Prompt("Please enter the full path to your desired environment variable file: ", "mad.env");
            state.EnvVarPrefix = Prompt("Please enter the environment variable prefix (default is 'MAD_')", "MAD_");

            if (!state.EnvVarPrefix.EndsWith("_"))
                state.EnvVarPrefix += "_";
        }

        state.ConfigFilePath = Prompt("Please enter the full path to your desired config file", state.Config.ConfigFile);
        state.LogFile = Prompt("Please enter the path to your log file", state.Config.LogFile);
    }

    public static void PromptAuditLogging(OobeState state)
    {
        state.AuditLoggingEnabled = PromptYesNo("Do you want to enable audit logging?");

        if (state.AuditLoggingEnabled)
        {
            var input = PromptInt("Number of days to retain audit logs (0 = forever)", state.Config.AuditLogRetentionDays, 0, 9999);
            state.AuditLogRetentionDays = input;
        }
    }

    public static void PromptAuthServerConfig(OobeState state)
    {
        state.AuthIp = Prompt("Enter the IP address for the AUTH server to bind to", state.Config.AuthIp);
        while (!Utils.IsValidIpAddress(state.AuthIp))
        {
            Console.WriteLine("Please enter a valid IP address!\n");
            state.AuthIp = Prompt("Enter the IP address for the AUTH server to bind to", state.Config.AuthIp);
        }

        state.AuthPort = PromptInt("Enter the port for the AUTH server", state.Config.AuthPort, 1, 65535);
        state.AuthDomain = Prompt("Enter the domain for the AUTH server", state.Config.AuthDomain);
        state.AuthSSLCertFile = Prompt("Path to AUTH SSL certificate (empty for HTTP)", state.Config.AuthSSLCertFile);
        if (!string.IsNullOrWhiteSpace(state.AuthSSLCertFile))
        {
            Console.Write("Enter passphrase for AUTH SSL cert (blank if none): ");
            state.AuthSSLCertPass = Utils.ReadHiddenInput();
        }
        else
        {
            state.AuthDomainNoSSL = !PromptYesNo("Do you use SSL on your external domain for AUTH?");
        }
    }

    public static void PromptAdminServerConfig(OobeState state)
    {
        state.AdminIp = Prompt("Enter the IP address for the ADMIN server to bind to", state.Config.AdminIp);
        while (!Utils.IsValidIpAddress(state.AdminIp))
        {
            Console.WriteLine("Please enter a valid IP address!\n");
            state.AdminIp = Prompt("Enter the IP address for the ADMIN server to bind to", state.Config.AdminIp);
        }

        state.AdminPort = PromptInt("Enter the port for the ADMIN server", state.Config.AdminPort, 1, 65535);
        state.AdminDomain = Prompt("Enter the domain for the ADMIN server", state.Config.AdminDomain);
        state.AdminSSLCertFile = Prompt("Path to ADMIN SSL certificate (empty for HTTP)", state.Config.AdminSSLCertFile);
        if (!string.IsNullOrWhiteSpace(state.AdminSSLCertFile))
        {
            Console.Write("Enter passphrase for ADMIN SSL cert (blank if none): ");
            state.AdminSSLCertPass = Utils.ReadHiddenInput();
        }
        else
        {
            state.AdminDomainNoSSL = !PromptYesNo("Do you use SSL on your external domain for ADMIN?");
        }
    }

    public static void PromptArgon2Config(OobeState state)
    {
        state.Argon2Time = PromptInt("Argon2 time cost", state.Config.Argon2Time, 1, 100);
        state.Argon2Memory = PromptInt("Argon2 memory cost (in KB)", state.Config.Argon2Memory, 8192, 1048576);
        state.Argon2Parallelism = PromptInt("Argon2 parallelism", state.Config.Argon2Parallelism, 1, 64);
        state.Argon2HashLength = PromptInt("Argon2 hash length", state.Config.Argon2HashLength, 16, 1024);
        state.Argon2SaltLength = PromptInt("Argon2 salt length", state.Config.Argon2SaltLength, 8, 1024);
    }

    public static void PromptTokenSigningConfig(OobeState state)
    {
        state.AuthTokenKeyPath = Prompt("Path to AUTH token signing key", state.Config.TokenSigningKeyFile);
        state.UseEcAuthSigner = PromptYesNo("Use EC certificates for AUTH tokens?");
        if (!state.UseEcAuthSigner)
        {
            state.AuthTokenKeyLength = PromptInt("AUTH RSA key length", state.Config.TokenSigningKeyLengthRSA, 2048, 16384);
        }
        Console.Write("Enter AUTH signing key passphrase (leave blank if none): ");
        state.AuthTokenKeyPass = Utils.ReadHiddenInput();

        state.AdminTokenKeyPath = Prompt("Path to ADMIN token signing key", state.Config.AdminTokenSigningKeyFile);
        state.UseEcAdminSigner = PromptYesNo("Use EC certificates for ADMIN tokens?");
        if (!state.UseEcAdminSigner)
        {
            state.AdminTokenKeyLength = PromptInt("ADMIN RSA key length", state.Config.AdminTokenSigningKeyLengthRSA, 2048, 16384);
        }
        Console.Write("Enter ADMIN signing key passphrase (leave blank if none): ");
        state.AdminTokenKeyPass = Utils.ReadHiddenInput();
    }

    public static void PromptTokenExpiryConfig(OobeState state)
    {
        state.AuthTokenExpiration = PromptInt("AUTH token expiration (seconds)", state.Config.TokenExpiration, 60, 604800);
        state.AdminTokenExpiration = PromptInt("ADMIN token expiration (seconds)", state.Config.AdminTokenExpiration, 60, 604800);
        state.TokenPurgeDays = PromptInt("Days to keep AUTH tokens after expiration (0 = forever)", 7, 0, 365);
    }

    public static void PromptFeatureFlags(OobeState state)
    {
        state.EnableRevocation = PromptYesNo("Enable token revocation?");
        state.EnableRefresh = PromptYesNo("Enable refresh tokens?");
        if (state.EnableRefresh)
        {
            state.RefreshTokenExpiration = PromptInt("Refresh token expiration (seconds)", state.Config.RefreshTokenExpiration, 300, 2592000);
            state.RefreshTokenPurgeDays = PromptInt("Days to keep refresh tokens after expiration (0 = forever)", 7, 0, 365);
        }
        state.EnableOtp = PromptYesNo("Enable OTP auth?");

        if (state.EnableOtp)
        {
            state.OtpIssuer = Prompt("Enter the OTP issuer name (e.g., your app name)", state.Config.OtpIssuer);
        }
    }

    public static void PromptLoginSecurity(OobeState state)
    {
        state.MaxLoginFailures = PromptInt("Max login failures before lockout", state.Config.MaxLoginFailures, 0, 100);
        state.SecondsToResetLoginFailures = PromptInt("Time to reset login failure count (seconds)", state.Config.SecondsToResetLoginFailures, 0, 86400);
        state.FailedPasswordLockoutDuration = PromptInt("Lockout duration after failed login (seconds)", state.Config.FailedPasswordLockoutDuration, 0, 86400);
    }

    public static void PromptOidcClient(OobeState state)
    {
        while (string.IsNullOrWhiteSpace(state.OidcClientId))
        {
            state.OidcClientId = Prompt("OIDC Client ID", "app");
            if (string.IsNullOrWhiteSpace(state.OidcClientId))
                Console.WriteLine("Client ID cannot be empty!\n");
        }

        while (string.IsNullOrWhiteSpace(state.OidcAudience))
        {
            state.OidcAudience = Prompt("OIDC Audience", "app");
            if (string.IsNullOrWhiteSpace(state.OidcAudience))
                Console.WriteLine("OIDC Audience cannot be empty!\n");
        }

        var secretLen = PromptInt("OIDC Client Secret length", 32, 16, 64);
        state.OidcClientSecret = AuthService.GeneratePassword(secretLen);

        Console.WriteLine($"\nClient created successfully.\nClient ID:     {state.OidcClientId}\nClient Secret: {state.OidcClientSecret}\nThis client secret will not be shown again, so please save it securely (press any key to continue)");
        Console.ReadKey(true);
    }

    public static void PromptAdminAccount(OobeState state)
    {
        while (string.IsNullOrWhiteSpace(state.AdminUser))
        {
            state.AdminUser = Prompt("Enter the username for the ADMIN user", "");
            if (string.IsNullOrWhiteSpace(state.AdminUser))
                Console.WriteLine("The ADMIN username cannot be empty!\n");
        }

        while (string.IsNullOrWhiteSpace(state.AdminEmail) || !Utils.IsValidEmail(state.AdminEmail))
        {
            state.AdminEmail = Prompt("Enter the email address for the ADMIN user", "");
            if (string.IsNullOrWhiteSpace(state.AdminEmail))
                Console.WriteLine("The ADMIN email cannot be empty!\n");
            else if (!Utils.IsValidEmail(state.AdminEmail))
                Console.WriteLine("Please enter a valid email address!\n");
        }

        while (string.IsNullOrWhiteSpace(state.AdminPass))
        {
            Console.Write("Enter the password for the ADMIN user: ");
            state.AdminPass = Utils.ReadHiddenInput();
            if (string.IsNullOrWhiteSpace(state.AdminPass))
                Console.WriteLine("The ADMIN password cannot be empty!\n");
        }
    }

    public static void PromptTrustedProxies(OobeState state)
    {
        var input = Prompt("Enter comma-separated list of trusted proxies (or leave blank for none)",
            string.Join(",", state.Config.TrustedProxies));

        state.TrustedProxies = input
            .Split(',', StringSplitOptions.RemoveEmptyEntries)
            .Select(p => p.Trim())
            .Where(p => !string.IsNullOrWhiteSpace(p))
            .ToList();
    }

    public static void PromptPkceConfig(OobeState state)
    {
        state.EnablePkce = PromptYesNo("Enable PKCE Login Flow?");

        if (state.EnablePkce)
            state.Argon2Time = PromptInt("PKCE Code Lifetime (in seconds)", state.Config.PkceCodeLifetime, 1, 600);        
    }

    public static void PromptPassCacheConfig(OobeState state)
    {
        state.EnablePassCache = PromptYesNo("Enable Password Caching?");

        if (state.EnablePassCache)
            state.Argon2Time = PromptInt("Password cache duration (in seconds)", state.Config.PassCacheDuration, 1, 600);
    }

    public static void PromptServePublicAuthFiles(OobeState state)
    {
        state.EnablePkce = PromptYesNo("Do you wish to serve public AUTH files from the /public root (will be accessible @ '/')?");        
    }

    public static void WriteConfig(OobeState state)
    {
        if (state.WriteEnvFile)
        {
            var lines = new List<string>
            {
                "# Configuration file for microauthd",
                "# This file follows classic kvp (ini-style) format",
                "# Example: key = value or key = \"value\"",
                "# Use '#' or ';' for comments\n",

                "# Environment variable prefix for configuration",
                $"env-var-prefix = { (string.IsNullOrEmpty(state.EnvVarPrefix) ? "MAD_" : state.EnvVarPrefix) }\n",
            };

            File.WriteAllLines(state.ConfigFilePath, lines);
            Console.WriteLine($"\nConfiguration written to {state.ConfigFilePath}\n");

            var envLines = new List<string>();

            envLines.Add("# Environment variables for microauthd");
            envLines.Add("# This file is auto-generated by the OOBE tool\n");
            envLines.Add($"{state.EnvVarPrefix}LOG_FILE=\"{state.LogFile}\"");
            envLines.Add($"{state.EnvVarPrefix}DB_FILE=\"{state.DbFilePath}\"");
            envLines.Add($"{state.EnvVarPrefix}DB_PASS=\"{state.DbPass}\"");
            envLines.Add($"{state.EnvVarPrefix}AUTH_IP={state.AuthIp}");
            envLines.Add($"{state.EnvVarPrefix}AUTH_PORT={state.AuthPort}");
            envLines.Add($"{state.EnvVarPrefix}AUTH_DOMAIN={state.AuthDomain}");
            envLines.Add($"{state.EnvVarPrefix}AUTH_SSL_CERT_FILE=\"{state.AuthSSLCertFile}\"");
            envLines.Add($"{state.EnvVarPrefix}AUTH_SSL_CERT_PASS=\"{state.AuthSSLCertPass}\"");
            envLines.Add($"{state.EnvVarPrefix}AUTH_DOMAIN_NO_SSL={state.AuthDomainNoSSL.ToString().ToLower()}");
            envLines.Add($"{state.EnvVarPrefix}ADMIN_IP={state.AdminIp}");
            envLines.Add($"{state.EnvVarPrefix}ADMIN_PORT={state.AdminPort}");
            envLines.Add($"{state.EnvVarPrefix}ADMIN_DOMAIN={state.AdminDomain}");
            envLines.Add($"{state.EnvVarPrefix}ADMIN_SSL_CERT_FILE=\"{state.AdminSSLCertFile}\"");
            envLines.Add($"{state.EnvVarPrefix}ADMIN_SSL_CERT_PASS=\"{state.AdminSSLCertPass}\"");
            envLines.Add($"{state.EnvVarPrefix}ADMIN_DOMAIN_NO_SSL={state.AdminDomainNoSSL.ToString().ToLower()}");
            envLines.Add($"{state.EnvVarPrefix}ARGON2_TIME={state.Argon2Time}");
            envLines.Add($"{state.EnvVarPrefix}ARGON2_MEMORY={state.Argon2Memory}");
            envLines.Add($"{state.EnvVarPrefix}ARGON2_PARALLELISM={state.Argon2Parallelism}");
            envLines.Add($"{state.EnvVarPrefix}ARGON2_HASH_LENGTH={state.Argon2HashLength}");
            envLines.Add($"{state.EnvVarPrefix}ARGON2_SALT_LENGTH={state.Argon2SaltLength}");
            envLines.Add($"{state.EnvVarPrefix}AUTH_TOKEN_KEY_PATH=\"{state.AuthTokenKeyPath}\"");
            envLines.Add($"{state.EnvVarPrefix}USE_EC_AUTH_SIGNER={(state.UseEcAuthSigner ? "true" : "false")}");
            if (!state.UseEcAuthSigner)
                envLines.Add($"{state.EnvVarPrefix}AUTH_TOKEN_KEY_LENGTH_RSA={state.AuthTokenKeyLength.ToString()}");
            envLines.Add($"{state.EnvVarPrefix}AUTH_TOKEN_KEY_PASS=\"{state.AuthTokenKeyPass}\"");
            envLines.Add($"{state.EnvVarPrefix}AUTH_TOKEN_EXPIRATION={state.AuthTokenExpiration}");
            envLines.Add($"{state.EnvVarPrefix}TOKEN_PURGE_DAYS={state.TokenPurgeDays}");
            envLines.Add($"{state.EnvVarPrefix}ENABLE_REVOCATION={(state.EnableRevocation ? "true" : "false")}");
            envLines.Add($"{state.EnvVarPrefix}ENABLE_REFRESH={(state.EnableRefresh ? "true" : "false")}");
            envLines.Add($"{state.EnvVarPrefix}REFRESH_TOKEN_EXPIRATION={state.RefreshTokenExpiration}");
            envLines.Add($"{state.EnvVarPrefix}REFRESH_TOKEN_PURGE_DAYS={state.RefreshTokenPurgeDays}");
            envLines.Add($"{state.EnvVarPrefix}ADMIN_TOKEN_KEY_PATH=\"{state.AdminTokenKeyPath}\"");
            envLines.Add($"{state.EnvVarPrefix}USE_EC_ADMIN_SIGNER={(state.UseEcAdminSigner ? "true" : "false")}");
            if (!state.UseEcAdminSigner)
                envLines.Add($"{state.EnvVarPrefix}ADMIN_TOKEN_KEY_LENGTH_RSA={(state.AdminTokenKeyLength)}");
            envLines.Add($"{state.EnvVarPrefix}ADMIN_TOKEN_SIGNING_KEY_PASS=\"{(state.AdminTokenKeyPass)}\"");
            envLines.Add($"{state.EnvVarPrefix}ADMIN_TOKEN_EXPIRATION={state.AdminTokenExpiration}");
            envLines.Add($"{state.EnvVarPrefix}ENABLE_AUTH_SWAGGER=false");
            envLines.Add($"{state.EnvVarPrefix}ENABLE_ADMIN_SWAGGER=false");
            envLines.Add($"{state.EnvVarPrefix}ENABLE_PKCE={state.EnablePkce.ToString().ToLower()}");
            envLines.Add($"{state.EnvVarPrefix}PKCE_CODE_LIFETIME={state.PkceCodeLifetime}");
            envLines.Add($"{state.EnvVarPrefix}ENABLE_OTP_AUTH={state.EnableOtp.ToString().ToLower()}");
            envLines.Add($"{state.EnvVarPrefix}OTP_ISSUER=\"{state.OtpIssuer}\"");
            envLines.Add($"{state.EnvVarPrefix}MAX_LOGIN_FAILURES={state.MaxLoginFailures}");
            envLines.Add($"{state.EnvVarPrefix}SECONDS_TO_RESET_LOGIN_FAILURES={state.SecondsToResetLoginFailures}");
            envLines.Add($"{state.EnvVarPrefix}FAILED_PASSWORD_LOCKOUT_DURATION={state.FailedPasswordLockoutDuration}");
            envLines.Add($"{state.EnvVarPrefix}ENABLE_AUDIT_LOGGING={state.AuditLoggingEnabled}");
            envLines.Add($"{state.EnvVarPrefix}AUDIT_LOG_RETENTION_DAYS={state.AuditLogRetentionDays}");
            envLines.Add($"{state.EnvVarPrefix}SERVE_PUBLIC_AUTH_FILES={state.ServePublicAuthFiles.ToString().ToLower()}");
            envLines.Add($"{state.EnvVarPrefix}ENABLE_PASS_CACHE={state.EnablePassCache.ToString().ToLower()}");
            envLines.Add($"{state.EnvVarPrefix}PASS_CACHE_DURATION={state.PassCacheDuration}\n");

            if (state.TrustedProxies.Any())
            {
                envLines.Add($"{state.EnvVarPrefix}TRUSTED_PROXIES = \"{string.Join(",", state.TrustedProxies)}\"");
            }

            File.WriteAllLines(state.EnvFilePath, envLines);
            Console.WriteLine($"\n.env file written to {state.EnvFilePath}\n");
        }
        else
        {
            var dbPassLine = string.IsNullOrEmpty(state.DbPass) ? "no-db-pass = true" : "no-db-pass = false";
            var authDomainNoSSLLine = $"auth-domain-no-ssl = {(state.AuthDomainNoSSL ? "true" : "false")}";
            var adminDomainNoSSLLine = $"admin-domain-no-ssl = {(state.AdminDomainNoSSL ? "true" : "false")}";

            var lines = new List<string>
            {
                "# Configuration file for microauthd",
                "# This file follows classic kvp (ini-style) format",
                "# Example: key = value or key = \"value\"",
                "# Use '#' or ';' for comments\n",

                "# Environment variable prefix for configuration",
                $"env-var-prefix = { (string.IsNullOrEmpty(state.EnvVarPrefix) ? "MAD_" : state.EnvVarPrefix) }\n",

                "# Log file",
                $"log-file = {state.LogFile}\n",

                "# Database config",
                $"db-file = {state.DbFilePath}",
                $"db-pass = {state.DbPass}",
                dbPassLine + "\n",

                "# Auth server config",
                $"auth-ip = {state.AuthIp}",
                $"auth-port = {state.AuthPort}",
                $"auth-domain = {state.AuthDomain}",
                $"auth-ssl-cert-file = {state.AuthSSLCertFile}",
                $"auth-ssl-cert-pass = {state.AuthSSLCertPass}",
                authDomainNoSSLLine + "\n",

                "# Admin server config",
                $"admin-ip = {state.AdminIp}",
                $"admin-port = {state.AdminPort}",
                $"admin-domain = {state.AdminDomain}",
                $"admin-ssl-cert-file = {state.AdminSSLCertFile}",
                $"admin-ssl-cert-pass = {state.AdminSSLCertPass}",
                adminDomainNoSSLLine + "\n",

                "# Argon2id config",
                $"argon2id-time = {state.Argon2Time}",
                $"argon2id-memory = {state.Argon2Memory}",
                $"argon2id-parallelism = {state.Argon2Parallelism}",
                $"argon2id-hash-length = {state.Argon2HashLength}",
                $"argon2id-salt-length = {state.Argon2SaltLength}\n",

                "# Auth Token config",
                $"token-signing-key-file = {state.AuthTokenKeyPath}",
                $"prefer-ec-token-signer = {state.UseEcAuthSigner.ToString().ToLower()}",
                $"token-signing-key-length-rsa = {state.AuthTokenKeyLength}",
                $"token-signing-key-pass = {state.AuthTokenKeyPass}",
                $"token-expiration = {state.AuthTokenExpiration}",
                $"token-purge-days = {state.TokenPurgeDays}",
                $"enable-token-revocation = {state.EnableRevocation.ToString().ToLower()}",
                $"enable-token-refresh = {state.EnableRefresh.ToString().ToLower()}",
                $"refresh-token-expiration = {state.RefreshTokenExpiration}",
                $"refresh-token-purge-days = {state.RefreshTokenPurgeDays}\n",

                "# Admin token config",
                $"admin-token-signing-key-file = {state.AdminTokenKeyPath}",
                $"prefer-ec-admin-token-signer = {state.UseEcAdminSigner.ToString().ToLower()}",
                $"admin-token-signing-key-length-rsa = {state.AdminTokenKeyLength}",
                $"admin-token-signing-key-pass = {state.AdminTokenKeyPass}",
                $"admin-token-expiration = {state.AdminTokenExpiration}\n",

                "# Swagger config",
                "enable-auth-swagger = false",
                "enable-admin-swagger = false\n",

                "# Pkce config",
                $"enable-pkce = {state.EnablePkce.ToString().ToLower()}",
                $"pkce-code-lifetime = {state.PkceCodeLifetime}\n",

                "# Miscellaneous config",
                $"enable-otp-auth = {state.EnableOtp.ToString().ToLower()}",
                $"otp-issuer = \"{state.OtpIssuer}\"",
                $"max-login-failures = {state.MaxLoginFailures}",
                $"seconds-to-reset-login-failures = {state.SecondsToResetLoginFailures}",
                $"failed-password-lockout-duration = {state.FailedPasswordLockoutDuration}",
                $"enable-audit-logging = {state.AuditLoggingEnabled}",
                $"audit-log-retention-days = {state.AuditLogRetentionDays}",
                $"serve-public-auth-files = {state.ServePublicAuthFiles.ToString().ToLower()}",
                $"enable-pass-cache = {state.EnablePassCache.ToString().ToLower()}",
                $"pass-cache-duration = {state.PassCacheDuration}\n",
            };

            if (state.TrustedProxies.Any())
            {
                lines.Add("# Trusted proxy IPs for forwarded header support");
                lines.Add($"trusted-proxies = {string.Join(",", state.TrustedProxies)}");
            }

            File.WriteAllLines(state.ConfigFilePath, lines);
            Console.WriteLine($"\nConfiguration written to {state.ConfigFilePath}\n");
        }
    }

    public static string Prompt(string message, string defaultValue)
    {
        Console.Write($"{message} [{defaultValue}]: ");
        var input = Console.ReadLine()?.Trim();
        return string.IsNullOrEmpty(input) ? defaultValue : input;
    }

    public static int PromptInt(string message, int defaultValue, int min, int max)
    {
        while (true)
        {
            Console.Write($"{message} [{defaultValue}]: ");
            var input = Console.ReadLine()?.Trim();
            if (string.IsNullOrEmpty(input)) return defaultValue;
            if (int.TryParse(input, out var value) && value >= min && value <= max)
                return value;
            Console.WriteLine($"Please enter a number between {min} and {max}.\n");
        }
    }

    public static bool PromptYesNo(string message)
    {
        while (true)
        {
            Console.Write($"{message} (y/n): ");
            var input = Console.ReadLine()?.Trim().ToLowerInvariant();
            if (input == "y" || input == "yes") return true;
            if (input == "n" || input == "no") return false;
            Console.WriteLine("Please enter 'y' or 'n'.");
        }
    }
}

