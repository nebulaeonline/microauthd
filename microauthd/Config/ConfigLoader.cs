using microauthd.CmdLine;
using System.Collections;
using System.CommandLine;
using System.CommandLine.Parsing;

namespace microauthd.Config;

public static class ConfigLoader
{
    /// <summary>
    /// Retrieves the default value for the specified option.
    /// </summary>
    /// <typeparam name="T">The type of the option's value.</typeparam>
    /// <param name="opt">The option for which to retrieve the default value. Cannot be null.</param>
    /// <returns>The default value of the specified option.</returns>
    private static T GetOptionDefault<T>(Option<T> opt)
    {
        return opt.Parse("").GetValueForOption(opt)!;
    }

    /// <summary>
    /// Loads the application configuration by combining values from the command-line arguments,  environment variables,
    /// and an optional configuration file.
    /// </summary>
    /// <remarks>The method prioritizes configuration values in the following order: 1. Command-line
    /// arguments. 2. Environment variables with the specified prefix. 3. Values from the configuration file, if it
    /// exists. 4. Default values for options, if none of the above sources provide a value.  Boolean values are
    /// interpreted as <see langword="true"/> if they are "1", "true", or "yes"  (case-insensitive) in the environment
    /// variables or configuration file.</remarks>
    /// <param name="cli">The parsed command-line arguments provided by the user.</param>
    /// <returns>An <see cref="AppConfig"/> instance containing the resolved configuration values.</returns>
    public static AppConfig Load(ParseResult cli)
    {
        string envPrefix = cli.GetValueForOption(Options.EnvVarPrefix)!;

        // Load env vars using the chosen prefix (we need this before config file)
        var env = GetEnvWithPrefix(envPrefix);

        // Resolve config file in correct order: CLI -> ENV -> fallback
        string? cliConfig = cli.HasOption(Options.ConfigFile)
            ? cli.GetValueForOption(Options.ConfigFile)
            : null;

        string? envConfig = env.TryGetValue("CONFIG", out var configFromEnv)
            ? configFromEnv
            : null;

        string configFile = cliConfig ?? envConfig ?? "mad.conf";

        // Parse config file if it exists
        var ini = File.Exists(configFile)
            ? SimpleIniParser.Parse(configFile)
            : new Dictionary<string, string>();

        if (!File.Exists(configFile))
        {
            Console.WriteLine($"[WARNING] Config file not found at '{configFile}', continuing with CLI/env only.");
        }

        // strongly typed accessors
        string GetString(Option<string> opt)
        {
            if (cli.WasOptionSpecified(opt))
                return cli.GetValueForOption(opt)!;
            if (env.TryGetValue(Options.EnvKeyFor(opt, envPrefix), out var val))
                return val;
            if (ini.TryGetValue(opt.Name, out var iniVal))
                return iniVal;
            return GetOptionDefault(opt);
        }

        int GetInt(Option<int> opt)
        {
            if (cli.WasOptionSpecified(opt))
                return cli.GetValueForOption(opt);
            if (env.TryGetValue(Options.EnvKeyFor(opt, envPrefix), out var val) && int.TryParse(val, out var parsed))
                return parsed;
            if (ini.TryGetValue(opt.Name, out var iniVal) && int.TryParse(iniVal, out var parsedIni))
                return parsedIni;
            return GetOptionDefault(opt);
        }

        bool GetBool(Option<bool> opt)
        {
            if (cli.WasOptionSpecified(opt))
                return cli.GetValueForOption(opt);
            if (env.TryGetValue(Options.EnvKeyFor(opt, envPrefix), out var val))
                return val is "1" or "true" or "yes";
            if (ini.TryGetValue(opt.Name, out var iniVal))
                return iniVal is "1" or "true" or "yes";
            return GetOptionDefault(opt);
        }

        string? GetOptional(Option<string> opt)
        {
            if (cli.WasOptionSpecified(opt))
                return cli.GetValueForOption(opt);
            if (env.TryGetValue(Options.EnvKeyFor(opt, envPrefix), out var val))
                return val;
            if (ini.TryGetValue(opt.Name, out var iniVal))
                return iniVal;
            return null;
        }

        List<string> GetStringList(Option<List<string>> opt)
        {
            if (cli.HasOption(opt) && cli.GetValueForOption(opt) is { } list && list.Count > 0)
                return list;

            if (env.TryGetValue(Options.EnvKeyFor(opt, envPrefix), out var val))
                return val.Split(',', StringSplitOptions.RemoveEmptyEntries).Select(x => x.Trim()).ToList();

            if (ini.TryGetValue(opt.Name, out var iniVal))
                return iniVal.Split(',', StringSplitOptions.RemoveEmptyEntries).Select(x => x.Trim()).ToList();

            return new();
        }

        return new AppConfig
        {
            ConfigFile = configFile,
            EnvVarPrefix = envPrefix,

            AuthIp = GetString(Options.AuthIp),
            AuthPort = GetInt(Options.AuthPort),
            AuthDomain = GetString(Options.AuthDomain),
            AuthSSLCertFile = GetString(Options.AuthSSLCertFile),
            AuthSSLCertPass = GetString(Options.AuthSSLCertPass),
            AuthDomainNoSSL = GetBool(Options.AuthDomainNoSSL),

            AdminIp = GetString(Options.AdminIp),
            AdminPort = GetInt(Options.AdminPort),
            AdminDomain = GetString(Options.AdminDomain),
            AdminSSLCertFile = GetString(Options.AdminSSLCertFile),
            AdminSSLCertPass = GetString(Options.AdminSSLCertPass),
            AdminDomainNoSSL = GetBool(Options.AdminDomainNoSSL),

            DbFile = GetString(Options.DbFile),
            DbPass = GetString(Options.DbPass),
            NoDbPass = GetBool(Options.NoDbPass),

            Argon2Time = GetInt(Options.Argon2idTime),
            Argon2Memory = GetInt(Options.Argon2idMemory),
            Argon2Parallelism = GetInt(Options.Argon2idParallelism),
            Argon2HashLength = GetInt(Options.Argon2idHashLength),
            Argon2SaltLength = GetInt(Options.Argon2idSaltLength),

            TokenSigningKeyFile = GetString(Options.TokenSigningKeyFile),
            PreferECDSASigningKey = GetBool(Options.PreferECDSASigningKey),
            TokenSigningKeyLengthRSA = GetInt(Options.TokenSigningKeyLengthRSA),
            AdminTokenSigningKeyFile = GetString(Options.AdminTokenSigningKeyFile),
            PreferECDSAAdminSigningKey = GetBool(Options.PreferECDSAAdminSigningKey),
            AdminTokenSigningKeyLengthRSA = GetInt(Options.AdminTokenSigningKeyLengthRSA),
            TokenSigningKeyPassphrase = GetOptional(Options.TokenSigningKeyPassphrase),
            AdminTokenSigningKeyPassphrase = GetOptional(Options.AdminTokenSigningKeyPassphrase),
            TokenExpiration = GetInt(Options.TokenExpirationTime),
            TokenPurgeDays = GetInt(Options.TokenPurgeDays),
            AdminTokenExpiration = GetInt(Options.AdminTokenExpirationTime),
            EnableTokenRevocation = GetBool(Options.EnableTokenRevocation),
            EnableTokenRefresh = GetBool(Options.EnableTokenRefresh),
            RefreshTokenExpiration = GetInt(Options.RefreshTokenExpiration),
            RefreshTokenPurgeDays = GetInt(Options.RefreshTokenPurgeDays),

            PrintEffectiveConfig = GetBool(Options.PrintEffectiveConfig),
            MaxLoginFailures = GetInt(Options.MaxLoginFailures),
            SecondsToResetLoginFailures = GetInt(Options.SecondsToResetLoginFailures),
            FailedPasswordLockoutDuration = GetInt(Options.FailedPasswordLockoutDuration),
            LogFile = GetString(Options.LogFile),
            EnableAuditLogging = GetBool(Options.EnableAuditLogging),
            AuditLogRetentionDays = GetInt(Options.AuditLogRetentionDays),
            EnableAuthSwagger = GetBool(Options.EnableAuthSwagger),
            EnableAdminSwagger = GetBool(Options.EnableAdminSwagger),
            TrustedProxies = GetStringList(Options.TrustedProxies),
            EnablePkce = GetBool(Options.EnablePkce),
            PkceCodeLifetime = GetInt(Options.PkceCodeLifetime),
            ServePublicAuthFiles = GetBool(Options.ServePublicAuthFiles),
            EnablePassCache = GetBool(Options.EnablePassCache),
            PassCacheDuration = GetInt(Options.PassCacheDuration),
            DockerMode = GetBool(Options.Docker),
        };
    }

    private static Dictionary<string, string> GetEnvWithPrefix(string prefix) =>
        Environment.GetEnvironmentVariables()
            .Cast<DictionaryEntry>()
            .Where(e => e.Key is string k && k.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            .ToDictionary(
                e => ((string)e.Key)[prefix.Length..].TrimStart('_'),
                e => e.Value?.ToString() ?? "",
                StringComparer.OrdinalIgnoreCase
            );
}
