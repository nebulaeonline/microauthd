using microauthd.Common;
using microauthd.Data;
using Serilog;

namespace microauthd.Config
{
    public static class OobeDos
    {
        public static (string adminUser, string adminEmail, string adminPass) LaunchOobe(AppConfig config)
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
                OobePrompts.WriteConfig(state);
            }

            OobePrompts.PromptAdminAccount(state);
                        
            Console.WriteLine("\nmicroauthd is now configured and ready.");
            Console.WriteLine($"Database file:  {state.DbFilePath}");
            Console.WriteLine($"Admin user:     {state.AdminUser}");

            Log.Information("OOBE completed successfully.");

            return (state.AdminUser, state.AdminEmail, state.AdminPass);
        }

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

            return userId;
        }
    }
}
