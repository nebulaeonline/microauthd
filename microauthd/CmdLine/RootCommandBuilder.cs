using System.CommandLine;

namespace microauthd.CmdLine;

public static class RootCommandBuilder
{
    public static RootCommand Build()
    {
        var root = new RootCommand("microauthd authentication daemon");

        // Global options
        root.AddGlobalOption(Options.ConfigFile);
        root.AddGlobalOption(Options.EnvVarPrefix);

        // Application-specific options
        root.AddOption(Options.AuthIp);
        root.AddOption(Options.AuthPort);
        root.AddOption(Options.AuthDomain);
        root.AddOption(Options.AuthSSLCertFile);
        root.AddOption(Options.AuthSSLCertPass);
        root.AddOption(Options.AuthDomainNoSSL);

        root.AddOption(Options.AdminIp);
        root.AddOption(Options.AdminPort);
        root.AddOption(Options.AdminDomain);
        root.AddOption(Options.AdminSSLCertFile);
        root.AddOption(Options.AdminSSLCertPass);
        root.AddOption(Options.AdminDomainNoSSL);

        root.AddOption(Options.DbFile);
        root.AddOption(Options.DbPass);
        root.AddOption(Options.NoDbPass);

        root.AddOption(Options.Argon2idTime);
        root.AddOption(Options.Argon2idMemory);
        root.AddOption(Options.Argon2idParallelism);
        root.AddOption(Options.Argon2idHashLength);
        root.AddOption(Options.Argon2idSaltLength);

        root.AddOption(Options.TokenSigningKeyFile);
        root.AddOption(Options.PreferECDSASigningKey);
        root.AddOption(Options.TokenSigningKeyLengthRSA);
        root.AddOption(Options.AdminTokenSigningKeyFile);
        root.AddOption(Options.PreferECDSAAdminSigningKey);
        root.AddOption(Options.AdminTokenSigningKeyLengthRSA);
        root.AddOption(Options.TokenSigningKeyPassphrase);
        root.AddOption(Options.AdminTokenSigningKeyPassphrase);
        root.AddOption(Options.TokenExpirationTime);
        root.AddOption(Options.AdminTokenExpirationTime);
        root.AddOption(Options.EnableTokenRevocation);
        root.AddOption(Options.EnableTokenRefresh);
        root.AddOption(Options.RefreshTokenExpiration);

        root.AddOption(Options.EnableOtpAuth);
        root.AddOption(Options.PrintEffectiveConfig);

        root.AddOption(Options.MaxLoginFailures);
        root.AddOption(Options.SecondsToResetLoginFailures);
        root.AddOption(Options.FailedPasswordLockoutDuration);
        root.AddOption(Options.LogFile);
        root.AddOption(Options.OidcIssuer);
        root.AddOption(Options.OidcClientId);
        root.AddOption(Options.OidcClientSecret);

        root.AddOption(Options.EnableAuthSwagger);
        root.AddOption(Options.EnableAdminSwagger);

        return root;
    }
}
