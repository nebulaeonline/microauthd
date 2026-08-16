using microauthd.CmdLine;
using microauthd.Common;
using microauthd.Config;
using microauthd.Data;
using microauthd.Hosting;
using microauthd.Logging;
using microauthd.Tokens;
using Microsoft.IdentityModel.JsonWebTokens;
using madTypes.Common;
using Serilog;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.CommandLine.Parsing;
using System.IdentityModel.Tokens.Jwt;

namespace microauthd;

public class Program
{
    public static async Task<int> Main(string[] args)
    {
        var root = RootCommandBuilder.Build();

        root.SetHandler(async (InvocationContext context) =>
        {
            var parseResult = context.ParseResult;
            var config = ConfigLoader.Load(parseResult);

            // Print effective configuration if requested
            if (config.PrintEffectiveConfig)
            {
                foreach (var prop in typeof(AppConfig).GetProperties())
                {
                    var value = prop.GetValue(config);
                    Console.WriteLine($"{prop.Name} = {value}");
                }
                Environment.Exit(0);
            }

            // Initialize logging
            LogSetup.Initialize(config);
            Log.Information("Starting microauthd with configuration: {Config}", config);
            ConfigLogger.LogSafeConfig(config);

            string adminUser = string.Empty;
            string adminEmail = string.Empty;
            string adminPass = string.Empty;

            // In docker mode, we have them run the oobe tool separately
            if (!config.DockerMode)
            {
                if (!File.Exists(config.DbFile))
                {
                    // See if our db file exists, if not, launch OOBE
                    var postConfig = OobeDos.LaunchOobe(config);
                    config = ConfigLoader.Load(parseResult); // Reload config after OOBE
                    DbInitializer.CreateDbTables(config);
                    DbMigrations.ApplyMigrations();

                    // Perform post-OOBE actions

                    // Set up the admin user
                    if (postConfig.NeedsAdminCreation)
                        OobeDos.CreateOobeUserRaw(postConfig.AdminUsername, postConfig.AdminEmail, postConfig.AdminPassword, config);

                    // Set up the initial OIDC client
                    if (postConfig.NeedsOidcClientCreation)
                        OobeDos.CreateOobeClientRaw(postConfig.InitialOidcClientId, postConfig.InitialOidcClientSecret, postConfig.InitialOidcAudience, config);
                }
                else
                {
                    // Initialize the database
                    DbInitializer.CreateDbTables(config);
                    DbMigrations.ApplyMigrations();
                    Db.FlushWal();
                }
            }
            else
            {
                // In Docker mode, we just error out if the database file doesn't exist
                if (!File.Exists(config.DbFile))
                {
                    Log.Fatal("Database file does not exist (running in Docker mode). Please initialize the database by running the madOobe tool.");
                    Console.Error.WriteLine("Database file does not exist in Docker mode. Please ensure the database is initialized.");
                    Environment.Exit(1);
                }
                else
                {
                    // Initialize the database
                    DbInitializer.CreateDbTables(config);
                    DbMigrations.ApplyMigrations();
                    Db.FlushWal();
                }
            }

            WarnAboutTotpQrOutputMigration(config);
            
            // Get our token signing keys in order; that includes
            // generating them if they don't exist, and exporting the
            // public keys 
            var authCertKeyId = TokenCertManager.EnsureAuthKeypair(config);
            var adminCertKeyId = TokenCertManager.EnsureAdminKeypair(config);

            // Validate the auth & admin server configurations
            if (!ValidateConfig.ValidateAuthConfig(config))
            {
                Environment.Exit(1);
            }

            if (!ValidateConfig.ValidateAdminConfig(config))
            {
                Environment.Exit(1);
            }

            // Sanity check: make sure the auth server and the admin
            // server are not using the same port
            if (config.AuthPort == config.AdminPort && config.AuthIp == config.AdminIp)
            {
                Log.Fatal("Auth and Admin services must be on different IP:port combinations.");
                Console.Error.WriteLine("Auth and Admin servers cannot bind to the same port on the same IP.");
                Environment.Exit(1);
            }

            // STOP .NET from renaming standard claims like "sub"
            JsonWebTokenHandler.DefaultInboundClaimTypeMap.Clear();

            // Initialize the token signing key cache
            TokenKeyCache.Initialize(config,  authCertKeyId, adminCertKeyId);

            // Run the servers concurrently
            await ServerHost.RunAsync(config, args);

            Environment.Exit(0);
        });

        return await root.InvokeAsync(args);
    }

    private static void WarnAboutTotpQrOutputMigration(AppConfig config)
    {
        const string migrationHelp =
            "Set 'totp-qr-output-root', '--totp-qr-output-root', or 'MAD_TOTP_QR_OUTPUT_ROOT' " +
            "to the absolute directory previously supplied by your QR-generation client.";

        if (string.IsNullOrWhiteSpace(config.TotpQrOutputRoot))
        {
            if (ClientFeaturesStore.IsFeatureEnabledForAnyClient(ClientFeatures.Flags.EnableTotp))
            {
                Log.Error(
                    "TOTP is enabled for one or more clients, but no trusted TOTP QR output root is configured. " +
                    "QR generation is disabled. {MigrationHelp}",
                    migrationHelp);
            }
            else
            {
                Log.Warning(
                    "No trusted TOTP QR output root is configured. QR file generation is disabled. " +
                    "If an older deployment supplied output paths in API requests, migration is required. {MigrationHelp}",
                    migrationHelp);
            }

            return;
        }

        if (!Path.IsPathRooted(config.TotpQrOutputRoot))
        {
            Log.Error(
                "The configured TOTP QR output root is not absolute; QR generation is disabled. {MigrationHelp}",
                migrationHelp);
            return;
        }

        Log.Information("TOTP QR output is restricted to trusted root {TotpQrOutputRoot}", Path.GetFullPath(config.TotpQrOutputRoot));
    }
}


