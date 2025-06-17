using microauthd.CmdLine;
using microauthd.Common;
using microauthd.Config;
using microauthd.Data;
using microauthd.Hosting;
using microauthd.Logging;
using microauthd.Tokens;
using Microsoft.IdentityModel.JsonWebTokens;
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

            // See if our db file exists, if not, launch OOBE
            if (!File.Exists(config.DbFile))
            {
                var postConfig = OobeDos.LaunchOobe(config);
                config = ConfigLoader.Load(parseResult); // Reload config after OOBE
                DbInitializer.CreateDbTables(config);
                
                // Perform post-OOBE actions

                // Set up the admin user
                if (postConfig.NeedsAdminCreation)
                    OobeDos.CreateOobeUserRaw(postConfig.AdminUsername, postConfig.AdminEmail, postConfig.AdminPassword, config);

                // Set up the initial OIDC client
                if (postConfig.NeedsOidcClientCreation)
                    OobeDos.CreateOobeClientRaw(postConfig.InitialOidcClientId, postConfig.InitialOidcClientSecret, config);
            }
            else
            {
                // Initialize the database
                DbInitializer.CreateDbTables(config);
            }               

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
}


