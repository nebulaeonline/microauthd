namespace microauthd.Config;

internal class OobeState
{
    public AppConfig Config;

    public string DbFilePath = string.Empty;
    public string ConfigFilePath = string.Empty;
    public string LogFile = string.Empty;
    public string DbPass = string.Empty;

    public bool FullSetup = false;

    public string AuthIp = string.Empty;
    public int AuthPort = 0;
    public string AuthDomain = string.Empty;
    public string? AuthSSLCertFile = string.Empty;
    public string? AuthSSLCertPass = string.Empty;
    public bool AuthDomainNoSSL = false;

    public string AdminIp = string.Empty;
    public int AdminPort = 0;
    public string AdminDomain = string.Empty;
    public string? AdminSSLCertFile = string.Empty;
    public string? AdminSSLCertPass = string.Empty;
    public bool AdminDomainNoSSL = false;

    public int Argon2Time = 0;
    public int Argon2Memory = 0;
    public int Argon2Parallelism = 0;
    public int Argon2HashLength = 0;
    public int Argon2SaltLength = 0;

    public bool UseEcAuthSigner = false;
    public bool UseEcAdminSigner = false;
    public string AuthTokenKeyPath = string.Empty;
    public string AuthTokenKeyPass = string.Empty;
    public int AuthTokenKeyLength = 0;
    public int AuthTokenExpiration = 0;

    public string AdminTokenKeyPath = string.Empty;
    public string AdminTokenKeyPass = string.Empty;
    public int AdminTokenKeyLength = 0;
    public int AdminTokenExpiration = 0;

    public bool EnableRevocation = false;
    public bool EnableRefresh = false;
    public int RefreshTokenExpiration = 0;
    public bool EnableOtp = false;

    public int MaxLoginFailures = 0;
    public int SecondsToResetLoginFailures = 0;
    public int FailedPasswordLockoutDuration = 0;

    public string OidcIssuer = string.Empty;
    public string OidcClientId = string.Empty;
    public string OidcClientSecret = string.Empty;
    public string OidcAudience = string.Empty;

    public bool AuditLoggingEnabled = false;
    public int AuditLogRetentionDays = 0;

    public string AdminUser = string.Empty;
    public string AdminEmail = string.Empty;
    public string AdminPass = string.Empty;

    public List<string> TrustedProxies = new();

    public bool EnablePkce = false;
    public int PkceCodeLifetime = 0;

    public bool ServePublicAuthFiles = false;

    public OobeState(AppConfig config)
    {
        Config = config;
    }
}
