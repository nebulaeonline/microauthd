using Serilog;

using microauthd.Common;
using microauthd.Data;
using microauthd.Services;

namespace microauthd.Config
{
    internal static class Oobe
    {
        public static void LaunchOobe(AppConfig config)
        {
            // File/config paths
            string? configFilePath = "";
            string? dbFilePath = "";
            string? authTokenSigningFile = "";
            string? authTokenPass = "";
            string? adminTokenSigningFile = "";
            string? adminTokenPass = "";
            string? logFile = "";
            string? oidcIssuer = "";
            string? authSSLCertFile = "";
            string? adminSSLCertFile = "";

            // IP/domain
            string? authIpStr = "";
            string? authDomain = "";
            string? adminIpStr = "";
            string? adminDomain = "";
 
            // Prompt answers (y/n)
            string? fullSetup = "";
            string? adminEnableRevocation = "";
            string? authEnableRefresh = "";
            string? authEnableOtp = "";
            string? adminDomainNoSSLStr = "";
            string? authDomainNoSSLStr = "";
            string? auditLoggingStr = "";
            string? auditLogRetentionDaysStr = "";

            // Ports and numeric config
            int authPort = 0;
            int adminPort = 0;
            int argon2Time = 0;
            int argon2Mem = 0;
            int argon2Parallelism = 0;
            int argon2HashLen = 0;
            int argon2SaltLen = 0;
            int authTokenExpiration = 0;
            int adminTokenExpiration = 0;
            int maxLoginFailures = 0;
            int maxLoginFailuresReset = 0;
            int failedPassLockoutDuration = 0;
            int authTokenSigningLen = 0;
            int adminTokenSigningLen = 0;
            int refreshTokenExpiration = 0;
            int auditLogDays = 0;

            // Admin credentials
            string? adminUser = "";
            string? adminEmail = "";
            string adminPass = "";
            string? oidcClientId = "";
            string randomClientSecret = "";
            string? authSSLCertPass = "";
            string? adminSSLCertPass = "";

            // DB password
            string dbPass = "";

            // Booleans
            bool authIpValid = false;
            bool authPortValid = false;
            bool adminIpValid = false;
            bool adminPortValid = false;
            bool argon2TimeValid = false;
            bool argon2MemValid = false;
            bool argon2ParallelismValid = false;
            bool argon2HashLenValid = false;
            bool argon2SaltLenValid = false;
            bool authTokenExpirationValid = false;
            bool adminTokenExpirationValid = false;
            bool maxLoginFailuresValid = false;
            bool maxLoginFailuresResetValid = false;
            bool failedPassLockoutDurationValid = false;
            bool useECAuthSigner = false;
            bool useECAdminSigner = false;
            bool authTokenSigningLenValid = false;
            bool adminTokenSigningLenValid = false;
            bool refreshTokenExpirationValid = false;
            bool authDomainNoSSL = false;
            bool adminDomainNoSSL = false;
            bool auditLogging = false;
            bool auditLogDaysValid = false;

            Console.WriteLine("Welcome to microauthd!");
            Console.WriteLine("=======================\n");

            Console.WriteLine("It looks like this is your first time running microauthd (or your database is missing).");
            Console.WriteLine("Let's walk through a few defaults and setup steps.\n");

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
            Console.WriteLine("This flexibility lets you run multiple instances however you prefer-");
            Console.WriteLine("we don’t assume anything like /etc or system-level conventions. You may even be on Windows or macOS.\n");

            Console.WriteLine("You must specify a database file and password, and create an admin user account. You will be given the");
            Console.WriteLine("option to do a guided setup to create your configuration file, but it is not required.\n");

            Console.WriteLine($"Please follow the prompts to configure your instance.\n");

            // Database file path
            Console.Write($"Please enter the full path to your desired database file [{config.DbFile}]: ");
            dbFilePath = Console.ReadLine()?.Trim() ?? string.Empty;

            if (dbFilePath == string.Empty || dbFilePath.Length == 0)
                dbFilePath = config.DbFile;

            // Database password
            oobe_db_pass:

            Console.Write($"Please enter a password for your database file [{config.DbPass}]: ");
            dbPass = Utils.ReadHiddenInput();

            if (string.IsNullOrEmpty(dbPass))
            {
                empty_db_pass_confirm:

                Console.Write("Are you sure you want to leave the database password empty? This is *not recommended*! (y/n):");
                var confirm = Console.ReadLine()?.Trim().ToLowerInvariant();

                if (confirm == "y" || confirm == "yes")
                {
                    dbPass = ""; // allow blank
                }
                else if (confirm == "n" || confirm == "no")
                {
                    goto oobe_db_pass;
                }
                else
                {
                    goto empty_db_pass_confirm;
                }
            }

            oobe_open:

            Console.Write($"Would you like to do a full setup and write a new configuration file? (if you choose no you will move to admin account creation, and you MUST remember to either (1) put your database file and password into your config file, (2) specify them via cli flags, or (3) use environment variables) (y/n): ");
            fullSetup = Console.ReadLine()?.ToLowerInvariant().Trim();

            while (fullSetup != "y" && fullSetup != "yes" && fullSetup != "n" && fullSetup != "no")
                goto oobe_open;

            if (fullSetup == "n" || fullSetup == "no")
                goto oobe_admin_username;

            // Config file path
            Console.Write($"Please enter the full path to your desired configuration file [{config.ConfigFile}]: ");

            configFilePath = Console.ReadLine()?.Trim();

            if (configFilePath is null || configFilePath.Length == 0)
                configFilePath = config.ConfigFile;

            // Log file path
            Console.Write($"Please enter the full path to your desired log file location (including filename) [{config.LogFile}]: ");

            logFile = Console.ReadLine()?.Trim();

            if (logFile is null || logFile.Length == 0)
                logFile = config.LogFile;

            // Audit logging
            oobe_audit_logging:

            Console.Write($"Do you want to enable audit logging? (y/n): ");
            auditLoggingStr = Console.ReadLine()?.ToLowerInvariant().Trim();

            while (auditLoggingStr != "y" && auditLoggingStr != "yes" && auditLoggingStr != "n" && auditLoggingStr != "no")
                goto oobe_audit_logging;

            if (fullSetup == "n" || fullSetup == "no")
                goto oobe_auth_ip;

            auditLogging = true;

            oobe_audit_logging_days:

            Console.Write($"Please enter the number of days to retain audit logs (0 - forever) [{config.AuditLogRetentionDays}]: ");
            var auditLogDaysStr = Console.ReadLine()?.Trim();

            if (auditLogDaysStr is null || auditLogDaysStr.Length == 0)
                auditLogDaysStr = config.AuthPort.ToString();

            auditLogDays = 0;
            auditLogDaysValid = int.TryParse(auditLogDaysStr, out auditLogDays);

            if (!auditLogDaysValid || auditLogDays < 0)
            {
                Console.WriteLine("Please enter a valid number of days!\n");
                goto oobe_audit_logging_days;
            }

            // IP address for authentication server
            oobe_auth_ip:

            Console.Write($"Please enter the IP address for the AUTH server to bind to [{config.AuthIp}]: ");
            authIpStr = Console.ReadLine()?.Trim();

            if (authIpStr is null || authIpStr.Length == 0)
                authIpStr = config.AuthIp;

            authIpValid = Utils.IsValidIpAddress(authIpStr);

            if (!authIpValid)
            {
                Console.WriteLine("Please enter a valid IP address!\n");
                goto oobe_auth_ip;
            }

            oobe_authport:

            // IP address for authentication server
            Console.Write($"Please enter the Port for the AUTH server to bind to [{config.AuthPort}]: ");
            var authPortStr = Console.ReadLine()?.Trim();

            if (authPortStr is null || authPortStr.Length == 0)
                authPortStr = config.AuthPort.ToString();

            authPort = 0;
            authPortValid = int.TryParse(authPortStr, out authPort);

            if (!authPortValid || authPort < 1 || authPort > 65535)
            {
                Console.WriteLine("Please enter a valid Port!\n");
                goto oobe_authport;
            }

            // Domain for authentication server
            Console.Write($"Please enter the domain for the AUTH server [{config.AuthDomain}]: ");
            authDomain = Console.ReadLine()?.Trim();

            if (authDomain is null || authDomain.Length == 0)
                authDomain = config.AuthDomain;

            // Use ssl on AUTH port
            Console.Write($"To use SSL for the AUTH server, you must have a valid SSL certificate.\nEnter the path to your SSL certificate here (or leave empty for HTTP if you're running a reverse proxy): ");
            authSSLCertFile = Console.ReadLine()?.Trim();

            if (string.IsNullOrEmpty(authSSLCertFile))
                goto oobe_use_ssl_on_external_auth_domain;

            Console.Write($"Please enter the passphrase for your AUTH SSL certificate (leave empty if none): ");
            authSSLCertPass = Utils.ReadHiddenInput();
            goto oobe_admin_ip;

            // Use ssl for external AUTH domain links
            oobe_use_ssl_on_external_auth_domain:

            Console.Write($"Do you use SSL on your domain for the AUTH server? (y/n): ");
            authDomainNoSSLStr = Console.ReadLine()?.ToLowerInvariant().Trim();

            while (authDomainNoSSLStr != "y" && authDomainNoSSLStr != "yes" && authDomainNoSSLStr != "n" && authDomainNoSSLStr != "no")
                goto oobe_use_ssl_on_external_auth_domain;

            if (authDomainNoSSLStr == "n" || authDomainNoSSLStr == "no")
                authDomainNoSSL = true;

            oobe_admin_ip:

            // IP address for administration server
            Console.Write($"Please enter the IP address for the ADMIN server to bind to [{config.AdminIp}]: ");
            adminIpStr = Console.ReadLine()?.Trim();

            if (adminIpStr is null || adminIpStr.Length == 0)
                adminIpStr = config.AdminIp;

            adminIpValid = Utils.IsValidIpAddress(adminIpStr);

            if (!adminIpValid)
            {
                Console.WriteLine("Please enter a valid IP address!\n");
                goto oobe_admin_ip;
            }

            oobe_adminport:

            // IP address for administration server
            Console.Write($"Please enter the Port for the ADMIN server to bind to [{config.AdminPort}]: ");
            var adminPortStr = Console.ReadLine()?.Trim();

            if (adminPortStr is null || adminPortStr.Length == 0)
                adminPortStr = config.AdminPort.ToString();

            adminPort = 0;
            adminPortValid = int.TryParse(adminPortStr, out adminPort);

            if (!adminPortValid || adminPort < 1 || adminPort > 65535)
            {
                Console.WriteLine("Please enter a valid Port!\n");
                goto oobe_adminport;
            }

            // Domain for administration server
            Console.Write($"Please enter the domain for the ADMIN server [{config.AdminDomain}]: ");
            adminDomain = Console.ReadLine()?.Trim();

            if (adminDomain is null || adminDomain.Length == 0)
                adminDomain = config.AdminDomain;

            // Use ssl on ADMIN port
            Console.Write($"To use SSL for the ADMIN server, you must have a valid SSL certificate.\nEnter the path to your SSL certificate here (or leave empty for HTTP if you're running a reverse proxy): ");
            adminSSLCertFile = Console.ReadLine()?.Trim();

            if (string.IsNullOrEmpty(adminSSLCertFile))
                goto oobe_admin_domain_use_ssl;

            Console.Write($"Please enter the passphrase for your ADMIN SSL certificate (leave empty if none): ");
            adminSSLCertPass = Utils.ReadHiddenInput();
            goto argon2_start;

            // Use ssl for external ADMIN domain links
            oobe_admin_domain_use_ssl:

            Console.Write($"Do you use SSL on your domain for the ADMIN server? (y/n): ");
            adminDomainNoSSLStr = Console.ReadLine()?.ToLowerInvariant().Trim();

            while (adminDomainNoSSLStr != "y" && adminDomainNoSSLStr != "yes" && adminDomainNoSSLStr != "n" && adminDomainNoSSLStr != "no")
                goto oobe_admin_domain_use_ssl;

            if (adminDomainNoSSLStr == "n" || adminDomainNoSSLStr == "no")
                adminDomainNoSSL = true;

            argon2_start:

            // argon2 parameters

            // argon2 time cost
            Console.Write($"Please enter the Argon2 time cost (default is current OWASP recommendation) [{config.Argon2Time}]: ");
            var argon2TimeCostStr = Console.ReadLine()?.Trim();

            if (argon2TimeCostStr is null || argon2TimeCostStr.Length == 0)
                argon2TimeCostStr = config.Argon2Time.ToString();

            argon2Time = 0;
            argon2TimeValid = int.TryParse(argon2TimeCostStr, out argon2Time);

            if (!argon2TimeValid)
            {
                Console.WriteLine("Please enter a valid argon2 time cost (or accept the default)!\n");
                goto argon2_start;
            }

            // argon2 memory cost
            argon2_mem_cost:

            Console.Write($"Please enter the Argon2 memory cost in KB (default is current OWASP recommendation) [{config.Argon2Memory}]: ");
            var argon2MemCostStr = Console.ReadLine()?.Trim();

            if (argon2MemCostStr is null || argon2MemCostStr.Length == 0)
                argon2MemCostStr = config.Argon2Memory.ToString();

            argon2Mem = 0;
            argon2MemValid = int.TryParse(argon2MemCostStr, out argon2Mem);

            if (!argon2MemValid)
            {
                Console.WriteLine("Please enter a valid argon2 memory cost in KB (or accept the default)!\n");
                goto argon2_mem_cost;
            }

            // argon2 parallelism factor
            argon2_parallelism:

            Console.Write($"Please enter the Argon2 parallelism factor (default is current OWASP recommendation) [{config.Argon2Parallelism}]: ");
            var argon2ParallelismStr = Console.ReadLine()?.Trim();

            if (argon2ParallelismStr is null || argon2ParallelismStr.Length == 0)
                argon2ParallelismStr = config.Argon2Parallelism.ToString();

            argon2Parallelism = 0;
            argon2ParallelismValid = int.TryParse(argon2ParallelismStr, out argon2Parallelism);

            if (!argon2ParallelismValid)
            {
                Console.WriteLine("Please enter a valid argon2 parallelism value (or accept the default)!\n");
                goto argon2_parallelism;
            }

            // argon2 hash length
            argon2_hash_len:

            Console.Write($"Please enter the Argon2 hash length (default is current OWASP recommendation) [{config.Argon2HashLength}]: ");
            var argon2HashLenStr = Console.ReadLine()?.Trim();

            if (argon2HashLenStr is null || argon2HashLenStr.Length == 0)
                argon2HashLenStr = config.Argon2HashLength.ToString();

            argon2HashLen = 0;
            argon2HashLenValid = int.TryParse(argon2HashLenStr, out argon2HashLen);

            if (!argon2HashLenValid || argon2HashLen < 16)
            {
                Console.WriteLine("Please enter a valid argon2 hash length >= 16 (or accept the default)!\n");
                goto argon2_hash_len;
            }

            // argon2 salt length
            argon2_salt_len:

            Console.Write($"Please enter the Argon2 salt length (default is current OWASP recommendation) [{config.Argon2SaltLength}]: ");
            var argon2SaltLenStr = Console.ReadLine()?.Trim();

            if (argon2SaltLenStr is null || argon2SaltLenStr.Length == 0)
                argon2SaltLenStr = config.Argon2SaltLength.ToString();

            argon2SaltLen = 0;
            argon2SaltLenValid = int.TryParse(argon2SaltLenStr, out argon2SaltLen);

            if (!argon2SaltLenValid || argon2SaltLen < 8)
            {
                Console.WriteLine("Please enter a valid argon2 salt length >= 8 (or accept the default)!\n");
                goto argon2_salt_len;
            }

            // Auth Token signing key file
            Console.Write($"Please enter the full path to your AUTH token signing key file; if the key file does not exist, it will be generated [{config.TokenSigningKeyFile}]: ");

            authTokenSigningFile = Console.ReadLine()?.Trim();

            if (authTokenSigningFile is null || authTokenSigningFile.Length == 0)
                authTokenSigningFile = config.TokenSigningKeyFile;

            // Auth token prefer EC signing key
            oobe_auth_use_ec:

            Console.Write($"Would you like to use EC-based certificates for signing tokens (instead of RSA)? (y/n): ");
            var useECAuthSignerStr = Console.ReadLine()?.ToLowerInvariant().Trim();

            if (useECAuthSignerStr != "y" && useECAuthSignerStr != "yes" && useECAuthSignerStr != "n" && useECAuthSignerStr != "no")
            {
                Console.WriteLine("Please enter 'y' or 'n'!\n");
                goto oobe_auth_use_ec;
            }

            if (useECAuthSignerStr == "y" || useECAuthSignerStr == "yes")
            {
                useECAuthSigner = true;
                goto oobe_auth_token_signing_key;
            }
            else
                useECAuthSigner = false;

            // Auth Token signing key length
            oobe_auth_rsa_len:

            Console.Write($"Please enter your desired AUTH RSA key length [{config.TokenSigningKeyLengthRSA}]: ");
            var authTokenSigningLenStr = Console.ReadLine()?.Trim();

            if (authTokenSigningLenStr is null || authTokenSigningLenStr.Length == 0)
                authTokenSigningLenStr = config.TokenSigningKeyLengthRSA.ToString();

            authTokenSigningLen = 0;
            authTokenSigningLenValid = int.TryParse(authTokenSigningLenStr, out authTokenSigningLen);

            if (!authTokenSigningLenValid || authTokenSigningLen < 2048 || authTokenSigningLen > 16384 || !Utils.IsPowerOfTwo(authTokenSigningLen))
            {
                Console.WriteLine("Please enter a valid RSA key length >= 2048 and <= 16384 (or accept the default)!\n");
                goto oobe_auth_rsa_len;
            }

            // Auth Token signing key passphrase
            oobe_auth_token_signing_key:

            Console.Write($"Please enter the passphrase for your AUTH token signing key (leave empty if none): ");
            authTokenPass = Utils.ReadHiddenInput();

            // Admin Token signing key file
            Console.Write($"Please enter the full path to your ADMIN token signing key file; if the key file does not exist, it will be generated [{config.AdminTokenSigningKeyFile}]: ");

            adminTokenSigningFile = Console.ReadLine()?.Trim();

            if (adminTokenSigningFile is null || adminTokenSigningFile.Length == 0)
                adminTokenSigningFile = config.AdminTokenSigningKeyFile;

            // Admin token prefer EC signing key
            oobe_admin_use_ec:

            Console.Write($"Would you like to use EC-based certificates for ADMIN signing tokens (instead of RSA)? (y/n): ");
            var useECAdminSignerStr = Console.ReadLine()?.ToLowerInvariant().Trim();

            if (useECAdminSignerStr != "y" && useECAdminSignerStr != "yes" && useECAdminSignerStr != "n" && useECAdminSignerStr != "no")
            {
                Console.WriteLine("Please enter 'y' or 'n'!\n");
                goto oobe_admin_use_ec;
            }

            if (useECAdminSignerStr == "y" || useECAdminSignerStr == "yes")
            {
                useECAdminSigner = true;
                goto admin_token_signing_key_pass;
            }
            else
                useECAdminSigner = false;

            // Admin Token signing key length
            oobe_admin_rsa_len:

            Console.Write($"Please enter your desired ADMIN RSA key length [{config.AdminTokenSigningKeyLengthRSA}]: ");
            var adminTokenSigningLenStr = Console.ReadLine()?.Trim();

            if (adminTokenSigningLenStr is null || adminTokenSigningLenStr.Length == 0)
                adminTokenSigningLenStr = config.AdminTokenSigningKeyLengthRSA.ToString();

            adminTokenSigningLen = 0;
            adminTokenSigningLenValid = int.TryParse(adminTokenSigningLenStr, out adminTokenSigningLen);

            if (!adminTokenSigningLenValid || adminTokenSigningLen < 2048 || adminTokenSigningLen > 16384 || !Utils.IsPowerOfTwo(adminTokenSigningLen))
            {
                Console.WriteLine("Please enter a valid RSA key length >= 2048 and <= 16384 (or accept the default)!\n");
                goto oobe_admin_rsa_len;
            }

            // Admin Token signing key passphrase
            admin_token_signing_key_pass:

            Console.Write($"Please enter the passphrase for your ADMIN token signing key (leave empty if none): ");
            adminTokenPass = Utils.ReadHiddenInput();

            // AUTH Token expiration
            oobe_auth_token_expiration:

            Console.Write($"Please enter the expiration time (in seconds) for AUTH tokens [{config.TokenExpiration}]: ");
            var authTokenExpirationStr = Console.ReadLine()?.Trim();

            if (authTokenExpirationStr is null || authTokenExpirationStr.Length == 0)
                authTokenExpirationStr = config.TokenExpiration.ToString();

            authTokenExpiration = 0;
            authTokenExpirationValid = int.TryParse(authTokenExpirationStr, out authTokenExpiration);

            if (!authTokenExpirationValid)
            {
                Console.WriteLine("Please enter a valid AUTH token expiration time (or accept the default)!\n");
                goto oobe_auth_token_expiration;
            }

            // ADMIN Token expiration
            oobe_admin_token_expiration:

            Console.Write($"Please enter the expiration time (in seconds) for ADMIN tokens [{config.AdminTokenExpiration}]: ");
            var adminTokenExpirationStr = Console.ReadLine()?.Trim();

            if (adminTokenExpirationStr is null || adminTokenExpirationStr.Length == 0)
                adminTokenExpirationStr = config.AdminTokenExpiration.ToString();

            adminTokenExpiration = 0;
            adminTokenExpirationValid = int.TryParse(adminTokenExpirationStr, out adminTokenExpiration);

            if (!adminTokenExpirationValid)
            {
                Console.WriteLine("Please enter a valid ADMIN token expiration time (or accept the default)!\n");
                goto oobe_admin_token_expiration;
            }

            // Enable token revocation
            oobe_enable_revocation:

            Console.Write($"Would you like to enable token revocation? (y/n): ");
            adminEnableRevocation = Console.ReadLine()?.ToLowerInvariant().Trim();

            while (adminEnableRevocation != "y" && adminEnableRevocation != "yes" && adminEnableRevocation != "n" && adminEnableRevocation != "no")
                goto oobe_enable_revocation;

            // Enable token refresh
            oobe_enable_refresh:

            Console.Write($"Would you like to enable token refresh? (y/n): ");
            authEnableRefresh = Console.ReadLine()?.ToLowerInvariant().Trim();

            while (authEnableRefresh != "y" && authEnableRefresh != "yes" && authEnableRefresh != "n" && authEnableRefresh != "no")
                goto oobe_enable_refresh;

            if (authEnableRefresh == "n" || authEnableRefresh == "no")
                goto oobe_enable_otpauth;

            // Refresh Token expiration
            oobe_refresh_token_expiration:

            Console.Write($"Please enter the expiration time (in seconds) for refresh tokens [{config.RefreshTokenExpiration}]: ");
            var refreshTokenExpirationStr = Console.ReadLine()?.Trim();

            if (refreshTokenExpirationStr is null || refreshTokenExpirationStr.Length == 0)
                refreshTokenExpirationStr = config.RefreshTokenExpiration.ToString();

            refreshTokenExpiration = 0;
            refreshTokenExpirationValid = int.TryParse(refreshTokenExpirationStr, out refreshTokenExpiration);

            if (!refreshTokenExpirationValid)
            {
                Console.WriteLine("Please enter a valid refresh token expiration time (or accept the default)!\n");
                goto oobe_refresh_token_expiration;
            }

            // Enable otp auth
            oobe_enable_otpauth:

            Console.Write($"Would you like to enable otp auth? (y/n): ");
            authEnableOtp = Console.ReadLine()?.ToLowerInvariant().Trim();

            while (authEnableOtp != "y" && authEnableOtp != "yes" && authEnableOtp != "n" && authEnableOtp != "no")
                goto oobe_enable_otpauth;

            // Max login failures
            oobe_auth_max_login_failures:

            Console.Write($"Please enter the max login failures [{config.MaxLoginFailures}]: ");
            var maxLoginFailuresStr = Console.ReadLine()?.Trim();

            if (maxLoginFailuresStr is null || maxLoginFailuresStr.Length == 0)
                maxLoginFailuresStr = config.MaxLoginFailures.ToString();

            maxLoginFailures = 0;
            maxLoginFailuresValid = int.TryParse(maxLoginFailuresStr, out maxLoginFailures);

            if (!maxLoginFailuresValid || maxLoginFailures < 0)
            {
                Console.WriteLine("Please enter a valid value for max login failures (or accept the default)!\n");
                goto oobe_auth_max_login_failures;
            }

            // Seconds to reset login failures
            oobe_auth_max_login_failures_reset:

            Console.Write($"Please enter the time to reset login failures (in seconds) [{config.SecondsToResetLoginFailures}]: ");
            var maxLoginFailuresResetStr = Console.ReadLine()?.Trim();

            if (maxLoginFailuresResetStr is null || maxLoginFailuresResetStr.Length == 0)
                maxLoginFailuresResetStr = config.SecondsToResetLoginFailures.ToString();

            maxLoginFailuresReset = 0;
            maxLoginFailuresResetValid = int.TryParse(maxLoginFailuresResetStr, out maxLoginFailuresReset);

            if (!maxLoginFailuresResetValid || maxLoginFailuresReset < 0)
            {
                Console.WriteLine("Please enter a valid value for time to reset login failures (or accept the default)!\n");
                goto oobe_auth_max_login_failures_reset;
            }

            // Failed password lockout duration
            oobe_auth_lockout_duration:

            Console.Write($"Please enter the lockout duration (in seconds) for failed logins [{config.FailedPasswordLockoutDuration}]: ");
            var failedPassLockoutDurationStr = Console.ReadLine()?.Trim();

            if (failedPassLockoutDurationStr is null || failedPassLockoutDurationStr.Length == 0)
                failedPassLockoutDurationStr = config.FailedPasswordLockoutDuration.ToString();

            failedPassLockoutDuration = 0;
            failedPassLockoutDurationValid = int.TryParse(failedPassLockoutDurationStr, out failedPassLockoutDuration);

            if (!failedPassLockoutDurationValid || failedPassLockoutDuration < 0)
            {
                Console.WriteLine("Please enter a valid value for lockout duration for failed logins (or accept the default)!\n");
                goto oobe_auth_lockout_duration;
            }

            // OIDC Issuer
            Console.Write($"Please enter the desired name of your OIDC issuer [{config.OidcIssuer}]: ");

            oidcIssuer = Console.ReadLine()?.Trim();

            if (oidcIssuer is null || oidcIssuer.Length == 0)
                oidcIssuer = config.OidcIssuer;

            // OIDC Client ID
            oobe_oidc_client_id:

            Console.Write($"Please enter the desired id for your OIDC client: ");

            oidcClientId = Console.ReadLine()?.Trim();

            if (oidcClientId is null || oidcClientId.Length == 0)
            {
                Console.WriteLine($"The OIDC client ID cannot be empty!");
                goto oobe_oidc_client_id;
            }

            // OIDC Client Secret
            oobe_oidc_client_secret_len:

            Console.Write($"How long should your OIDC client secret be? (16 minimum, 32 recommended, 64 maximum): [32]");
            var clientSecretLengthStr = Console.ReadLine()?.Trim() ?? "32";
            int clientSecretLength = 0;
            if (!int.TryParse(clientSecretLengthStr, out clientSecretLength) || clientSecretLength < 16 || clientSecretLength > 64)
            {
                Console.WriteLine($"Please enter a valid length between 16 and 64 (or accept the default of 32)!\n");
                goto oobe_oidc_client_secret_len;
            }

            randomClientSecret = AuthService.GeneratePassword(clientSecretLength);
            Console.WriteLine($"\nClient created successfully.");
            Console.WriteLine($"Client ID:     {oidcClientId}");
            Console.WriteLine($"Client secret: {randomClientSecret}\n");
            Console.WriteLine($"(press any key to continue)");
            Console.ReadKey(true);

            var dbPassLine = $"no-db-pass = ";
            if (dbPass.Length == 0)
                dbPassLine += "true";
            else
                dbPassLine += "false";

            var authDomainNoSSLLine = "";
            if (authDomainNoSSL)
                authDomainNoSSLLine = "auth-domain-no-ssl = true";
            else
                authDomainNoSSLLine = "auth-domain-no-ssl = false";

            var adminDomainNoSSLLine = "";
            if (adminDomainNoSSL)
                adminDomainNoSSLLine = "admin-domain-no-ssl = true";
            else
                adminDomainNoSSLLine = "admin-domain-no-ssl = false";

            // Collect all configuration values into a list of strings
            var configLines = new List<string>
            {
                $"# Configuration file for microauthd",
                $"# This file follows classic kvp (ini-style) format",
                $"# Example: key = value or key = \"value\"",
                $"# Use '#' or ';' for comments\n",
                $"# Environment variable prefix for configuration",
                $"env-var-prefix = \"MAD_\"\n",
                $"# Log file",
                $"log-file = {logFile}\n",
                $"# Database config",
                $"db-file = {dbFilePath}",
                $"db-pass = {dbPass}",
                $"{dbPassLine}\n",
                $"# Auth server config",
                $"auth-ip = {authIpStr}",
                $"auth-port = {authPort}",
                $"auth-domain = {authDomain}",
                $"auth-ssl-cert-file = {authSSLCertFile}",
                $"auth-ssl-cert-pass = {authSSLCertPass}",
                authDomainNoSSLLine,
                $"# Admin server config",
                $"admin-ip = {adminIpStr}",
                $"admin-port = {adminPort}",
                $"admin-domain = {adminDomain}",
                $"admin-ssl-cert-file = {adminSSLCertFile}",
                $"admin-ssl-cert-pass = {adminSSLCertPass}",
                adminDomainNoSSLLine,
                $"# Argon2id config",
                $"argon2id-time = {argon2Time}",
                $"argon2id-memory = {argon2Mem}",
                $"argon2id-parallelism = {argon2Parallelism}",
                $"argon2id-hash-length = {argon2HashLen}",
                $"argon2id-salt-length = {argon2SaltLen}\n",
                $"# Auth Token config",
                $"token-signing-key-file = {authTokenSigningFile}",
                $"prefer-ec-token-signer = {useECAuthSigner}",
                $"token-signing-key-length-rsa = {authTokenSigningLen}",
                $"token-signing-key-pass = {authTokenPass}",
                $"token-expiration = {authTokenExpiration}",
                $"enable-token-revocation = {adminEnableRevocation}",
                $"enable-token-refresh = {authEnableRefresh}",
                $"refresh-token-expiration = {refreshTokenExpiration}\n",
                $"# Admin token config",
                $"admin-token-signing-key-file = {adminTokenSigningFile}",
                $"prefer-ec-admin-token-signer = {useECAdminSigner}",
                $"admin-token-signing-key-length-rsa = {adminTokenSigningLen}",
                $"admin-token-signing-key-pass = {adminTokenPass}",
                $"admin-token-expiration = {adminTokenExpiration}\n",
                $"# OIDC config",
                $"oidc-issuer = {oidcIssuer}",
                $"oidc-client-id = {oidcClientId}",
                $"oidc-client-secret = {randomClientSecret}\n",
                $"# Swagger config",
                $"enable-auth-swagger = false",
                $"enable-admin-swagger = false\n",
                $"# Miscellaneous config",
                $"enable-otp-auth = {authEnableOtp}",
                $"max-login-failures = {maxLoginFailures}",
                $"seconds-to-reset-login-failures = {maxLoginFailuresReset}",
                $"failed-password-lockout-duration = {failedPassLockoutDuration}"
            };

            // Write the configuration to the specified config file
            File.WriteAllLines(configFilePath, configLines);
            Console.WriteLine($"\nConfiguration written to {configFilePath}\n");

            // Admin username
            oobe_admin_username:

            Console.Write($"Please enter the username for the ADMIN user: ");
            adminUser = Console.ReadLine()?.Trim();

            if (adminUser is null || adminUser.Length == 0)
            {
                Console.WriteLine("The ADMIN username cannot be empty!\n");
                goto oobe_admin_username;
            }

            // Admin email
            oobe_admin_email:

            Console.Write($"Please enter the email address for the ADMIN user: ");
            adminEmail = Console.ReadLine()?.Trim();

            if (adminEmail is null || adminEmail.Length == 0)
            {
                Console.WriteLine("The ADMIN email cannot be empty!\n");
                goto oobe_admin_email;
            }

            if (!Utils.IsValidEmail(adminEmail))
            {
                Console.WriteLine("Please enter a valid email address!\n");
                goto oobe_admin_email;
            }

            // Admin password
            oobe_admin_pass:

            Console.Write($"Please enter the password for the ADMIN user: ");
            adminPass = Utils.ReadHiddenInput();

            if (adminPass is null || adminPass.Length == 0)
            {
                Console.WriteLine("The ADMIN password cannot be empty!\n");
                goto oobe_admin_pass;
            }

            // Create the database file and tables
            DbInitializer.CreateDbTables(config);

            // Create the admin user
            UserService.CreateUser(adminUser, adminEmail, adminPass, config);

            // Add the MadAdmin role to the admin user
            RoleService.AddRoleToUser(adminUser, "MadAdmin", config);
                    
            // Print basic config summary
            Console.WriteLine("\nmicroauthd is now configured and ready.");
            Console.WriteLine($"➡ Database file:  {dbFilePath}");
            Console.WriteLine($"➡ Admin user:     {adminUser}");

            Log.Information("OOBE completed successfully.");
        }
    }
}
