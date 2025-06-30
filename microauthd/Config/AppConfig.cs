namespace microauthd.Config;

public class AppConfig
{
    public string ConfigFile { get; set; } = string.Empty;
    public string EnvVarPrefix { get; set; } = string.Empty;

    public string AuthIp { get; set; } = string.Empty;
    public int AuthPort { get; set; } = 0;
    public string AuthDomain { get; set; } = string.Empty;
    public string AuthSSLCertFile { get; set; } = string.Empty;
    public string AuthSSLCertPass { get; set; } = string.Empty;
    public bool AuthDomainNoSSL { get; set; } = false;

    public string AdminIp { get; set; } = string.Empty;
    public int AdminPort { get; set; } = 0;
    public string AdminDomain { get; set; } = string.Empty;
    public string AdminSSLCertFile { get; set; } = string.Empty;
    public string AdminSSLCertPass { get; set; } = string.Empty;
    public bool AdminDomainNoSSL { get; set; } = false;

    public string DbFile { get; set; } = string.Empty;
    public string DbPass { get; set; } = string.Empty;
    public bool NoDbPass { get; set; } = false;

    public int Argon2Time { get; set; } = 0;
    public int Argon2Memory { get; set; } = 0;
    public int Argon2Parallelism { get; set; } = 0;
    public int Argon2HashLength { get; set; } = 0;
    public int Argon2SaltLength { get; set; } = 0;

    public string TokenSigningKeyFile { get; set; } = string.Empty;
    public bool PreferECDSASigningKey { get; set; } = false;
    public int TokenSigningKeyLengthRSA { get; set; } = 0;
    public string AdminTokenSigningKeyFile { get; set; } = string.Empty;
    public bool PreferECDSAAdminSigningKey { get; set; } = false;
    public int AdminTokenSigningKeyLengthRSA { get; set; } = 0;
    public string? TokenSigningKeyPassphrase { get; set; } 
    public string? AdminTokenSigningKeyPassphrase { get; set; }
    public int TokenExpiration { get; set; } = 0;
    public int AdminTokenExpiration { get; set; } = 0;
    public bool EnableTokenRevocation { get; set; } = false;
    public bool EnableTokenRefresh { get; set; } = false;
    public int RefreshTokenExpiration { get; set; } = 0;

    public bool EnableOtpAuth { get; set; } = false;

    public bool PrintEffectiveConfig { get; set; } = false;

    public int MaxLoginFailures { get; set; } = 0;
    public int SecondsToResetLoginFailures { get; set; } = 0;
    public int FailedPasswordLockoutDuration { get; set; } = 0;
    public string LogFile { get; set; } = string.Empty;
    public bool EnableAuditLogging { get; set; } = false;
    public int AuditLogRetentionDays { get; set; } = 0;

    public string OidcIssuer
    {
        get
        {
            var scheme = AuthDomainNoSSL ? "http" : "https";
                return $"{scheme}://{AuthDomain}";
        }
    }

    public bool EnableAuthSwagger { get; set; } = false;
    public bool EnableAdminSwagger { get; set; } = false;

    public List<string> TrustedProxies { get; set; } = new();

    public bool EnablePkce { get; set; } = false;
    public int PkceCodeLifetime { get; set; } = 0;

    public bool ServePublicAuthFiles { get; set; } = false;

    public bool EnablePassCache { get; set; } = false;
    public int PassCacheDuration { get; set; } = 0;

    public bool DockerMode { get; set; } = false;
}