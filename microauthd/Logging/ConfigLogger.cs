using Serilog;

using microauthd.Config;

namespace microauthd.Logging
{
    internal class ConfigLogger
    {
        public static void LogSafeConfig(AppConfig config)
        {
            Log.Information("microauthd starting with configuration:\n{Config}", new
            {
                config.DbFile,
                DbPass = "<REDACTED>",
                config.AuthIp,
                config.AuthPort,
                config.AdminIp,
                config.AdminPort,
                config.Argon2Time,
                config.Argon2Memory,
                config.Argon2Parallelism,
                config.TokenExpiration,
                config.AdminTokenExpiration,
                config.EnableTokenRevocation,
                config.EnableTokenRefresh,
                config.EnableOtpAuth,
                config.MaxLoginFailures,
                config.FailedPasswordLockoutDuration,
            });
        }
    }
}
