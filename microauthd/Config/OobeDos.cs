using microauthd.Common;
using microauthd.Data;
using microauthd.Services;
using nebulae.dotArgon2;
using Serilog;
using System.Text;
using static nebulae.dotArgon2.Argon2;

namespace microauthd.Config
{
    public static class OobeDos
    {
        public static PostConfigSettings LaunchOobe(AppConfig config)
        {
            var state = new OobeState(config);
            OobePrompts.PrintIntro();
            OobePrompts.PromptDbPathAndPassword(state);
            OobePrompts.AskFullSetup(state);

            if (state.FullSetup)
            {
                OobePrompts.PromptConfigPaths(state);
                OobePrompts.PromptAuditLogging(state);
                OobePrompts.PromptAuthServerConfig(state);
                OobePrompts.PromptAdminServerConfig(state);
                OobePrompts.PromptArgon2Config(state);
                OobePrompts.PromptTokenSigningConfig(state);
                OobePrompts.PromptTokenExpiryConfig(state);
                OobePrompts.PromptFeatureFlags(state);
                OobePrompts.PromptLoginSecurity(state);
                OobePrompts.PromptOidcClient(state);
                OobePrompts.PromptTrustedProxies(state);
                OobePrompts.PromptServePublicAuthFiles(state);
                OobePrompts.PromptPkceConfig(state);
                OobePrompts.WriteConfig(state);
            }

            OobePrompts.PromptAdminAccount(state);
                        
            Console.WriteLine("\nmicroauthd is now configured and ready.");
            Console.WriteLine($"Database file:  {state.DbFilePath}");
            Console.WriteLine($"Admin user:     {state.AdminUser}");

            Log.Information("OOBE completed successfully.");

            // Set up our post-configuration settings
            var postConfig = new PostConfigSettings
            {
                AdminUsername = state.AdminUser,
                AdminEmail = state.AdminEmail,
                AdminPassword = state.AdminPass,
                InitialOidcClientId = state.OidcClientId,
                InitialOidcClientSecret = state.OidcClientSecret,
                InitialOidcAudience = state.OidcAudience
            };

            return postConfig;
        }

        // For creating the Admin user immediately post-OOBE
        public static string CreateOobeUserRaw(string username, string email, string password, AppConfig config)
        {
            var userId = Guid.NewGuid().ToString();
            var passwordHash = AuthService.HashPassword(password, config);

            Db.WithConnection(conn =>
            {
                // Step 1: Insert user directly
                using (var cmd = conn.CreateCommand())
                {
                    cmd.CommandText = """
                        INSERT INTO users (id, username, password_hash, email, created_at, is_active)
                        VALUES ($id, $username, $hash, $email, datetime('now'), 1);
                    """;
                    cmd.Parameters.AddWithValue("$id", userId);
                    cmd.Parameters.AddWithValue("$username", username);
                    cmd.Parameters.AddWithValue("$hash", passwordHash);
                    cmd.Parameters.AddWithValue("$email", email);
                    cmd.ExecuteNonQuery();
                }

                // Step 2: Assign MadAdmin role (by ID)
                using (var cmd = conn.CreateCommand())
                {
                    cmd.CommandText = """
                        INSERT INTO user_roles (id, user_id, role_id, assigned_at, is_active)
                        VALUES ($id, $uid, $rid, datetime('now'), 1);
                    """;
                    cmd.Parameters.AddWithValue("$id", Guid.NewGuid().ToString());
                    cmd.Parameters.AddWithValue("$uid", userId);
                    cmd.Parameters.AddWithValue("$rid", Constants.MadAdmin);
                    cmd.ExecuteNonQuery();
                }
            });

            Log.Information("OOBE: Created initial Admin user '{username}'", username);

            return userId;
        }

        // For creating the initial OIDC client immediately post-OOBE
        public static void CreateOobeClientRaw(string clientId, string clientSecret, string audience, AppConfig config)
        {
            if (string.IsNullOrWhiteSpace(clientId))
                throw new ArgumentException("Client ID must not be empty", nameof(clientId));
            if (string.IsNullOrWhiteSpace(clientSecret))
                throw new ArgumentException("Client secret must not be empty", nameof(clientSecret));
            if (string.IsNullOrWhiteSpace(audience))
                throw new ArgumentException("Audience must not be empty", nameof(audience));

            var id = Guid.NewGuid().ToString();
            var hash = Argon2.Argon2HashEncodedToString(
                Argon2Algorithm.Argon2id,
                (uint)config.Argon2Time,
                (uint)config.Argon2Memory,
                (uint)config.Argon2Parallelism,
                Encoding.UTF8.GetBytes(clientSecret),
                Utils.GenerateSalt(config.Argon2SaltLength),
                config.Argon2HashLength
            );

            Db.WithConnection(conn =>
            {
                using var cmd = conn.CreateCommand();
                cmd.CommandText = """
                    INSERT INTO clients (id, client_identifier, client_secret_hash, display_name, audience, created_at, modified_at, is_active)
                    VALUES ($id, $cid, $hash, $cid, $aud, datetime('now'), datetime('now'), 1);
                """;
                cmd.Parameters.AddWithValue("$id", id);
                cmd.Parameters.AddWithValue("$cid", clientId);
                cmd.Parameters.AddWithValue("$aud", audience);
                cmd.Parameters.AddWithValue("$hash", hash);
                cmd.ExecuteNonQuery();
            });

            Log.Information("OOBE: Created initial client '{ClientId}'", clientId);
        }
    }
}
