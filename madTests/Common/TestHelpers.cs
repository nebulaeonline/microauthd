using microauthd.Config;
using Microsoft.Extensions.Configuration;

namespace madTests.Common;

public static class TestHelpers
{
    public static AppConfig GetTestConfig(Action<AppConfig>? overrides = null)
    {
        var config = new AppConfig
        {
            ConfigFile = "test.conf",
            EnvVarPrefix = "TEST",

            AuthIp = "127.0.0.1",
            AuthPort = 9040,
            AuthDomain = "localhost",
            AuthSSLCertFile = "",
            AuthSSLCertPass = "",
            AuthDomainNoSSL = true,

            AdminIp = "127.0.0.1",
            AdminPort = 9041,
            AdminDomain = "localhost",
            AdminSSLCertFile = "",
            AdminSSLCertPass = "",
            AdminDomainNoSSL = true,

            DbFile = "test.db3",
            DbPass = "1234",
            NoDbPass = false,

            Argon2Time = 2,
            Argon2Memory = 32768,
            Argon2Parallelism = 2,
            Argon2HashLength = 32,
            Argon2SaltLength = 16,

            TokenSigningKeyFile = "token.pem",
            PreferECDSASigningKey = false,
            TokenSigningKeyLengthRSA = 2048,
            AdminTokenSigningKeyFile = "admin_token.pem",
            PreferECDSAAdminSigningKey = false,
            AdminTokenSigningKeyLengthRSA = 2048,
            TokenSigningKeyPassphrase = null,
            AdminTokenSigningKeyPassphrase = null,
            TokenExpiration = 3600,
            AdminTokenExpiration = 7200,
            EnableTokenRevocation = true,
            EnableTokenRefresh = true,
            RefreshTokenExpiration = 86400,

            PrintEffectiveConfig = false,
            MaxLoginFailures = 5,
            SecondsToResetLoginFailures = 300,
            FailedPasswordLockoutDuration = 900,
            LogFile = "test.log",
            EnableAuditLogging = false,
            AuditLogRetentionDays = 7,
            EnableAuthSwagger = false,
            EnableAdminSwagger = false,
            TrustedProxies = new List<string>(),
            EnablePkce = true,
            PkceCodeLifetime = 300,
            ServePublicAuthFiles = true,
            EnablePassCache = true,
            PassCacheDuration = 300,
        };

        overrides?.Invoke(config);
        return config;
    }
}
