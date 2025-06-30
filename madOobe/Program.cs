using microauthd.CmdLine;
using microauthd.Config;
using microauthd.Data;
using System.CommandLine;
using System.CommandLine.Invocation;

namespace madOobe
{
    internal class Program
    {
        static async Task<int> Main(string[] args)
        {
            Console.WriteLine("Launching microauthd OOBE setup...\n");

            var root = RootCommandBuilder.Build();

            root.SetHandler(async (InvocationContext context) =>
            {
                var parseResult = context.ParseResult;
                var config = ConfigLoader.Load(parseResult);

                try
                {
                    var postConfigSetupVars = OobeDos.LaunchOobe(config);
                    config = ConfigLoader.Load(parseResult); // Reload config after OOBE
                    DbInitializer.CreateDbTables(config);
                    DbMigrations.ApplyMigrations();

                    // Perform post-OOBE actions

                    // Set up the admin user
                    if (postConfigSetupVars.NeedsAdminCreation)
                        OobeDos.CreateOobeUserRaw(postConfigSetupVars.AdminUsername, postConfigSetupVars.AdminEmail, postConfigSetupVars.AdminPassword, config);

                    // Set up the initial OIDC client
                    if (postConfigSetupVars.NeedsOidcClientCreation)
                        OobeDos.CreateOobeClientRaw(postConfigSetupVars.InitialOidcClientId, postConfigSetupVars.InitialOidcClientSecret, postConfigSetupVars.InitialOidcAudience, config);

                    Console.WriteLine("\nSetup complete.");
                    Console.WriteLine($"Admin user: {postConfigSetupVars?.AdminUsername ?? "(unknown)"}");
                    Console.WriteLine($"Config file: {config.ConfigFile}");
                    Console.WriteLine($"Database file: {config.DbFile}");
                    Console.WriteLine("You can now run `microauthd` to start the server.");
                }
                catch (Exception ex)
                {
                    Console.WriteLine("OOBE failed: " + ex.Message);
                }
            });

            return await root.InvokeAsync(args);
        }
    }
}
