using microauthd.Config;
using Serilog;
using System.Security.Claims;

namespace microauthd.Data
{
    public static class AuthStore
    {
        /// <summary>
        /// Retrieves a list of claims associated with the specified user.
        /// </summary>
        /// <remarks>This method fetches claims based on the user's active roles and scopes from the
        /// database. Claims are generated for roles and scopes that are marked as active for both the user and the
        /// respective entities.</remarks>
        /// <param name="userId">The unique identifier of the user whose claims are to be retrieved.</param>
        /// <returns>A list of <see cref="Claim"/> objects representing the user's roles and scopes. Each claim will have a type
        /// of "role" or "scope" and a value corresponding to the role or scope ID.</returns>
        public static List<Claim> GetUserClaims(string userId)
        {
            var claims = new List<Claim>();

            foreach (var role in RoleStore.GetUserRoles(userId))
                claims.Add(new Claim("role", role));

            foreach (var scope in ScopeStore.GetUserScopes(userId))
                claims.Add(new Claim("scope", scope));

            return claims;
        }

        /// <summary>
        /// Records a failed login attempt for the specified user and updates their account status accordingly.
        /// </summary>
        /// <remarks>This method increments the failed login attempt counter for the user and determines
        /// whether the account  should be locked based on the configured maximum number of allowed failed attempts and
        /// lockout duration.  If the last failed login attempt occurred outside the reset window, the counter is
        /// reset.</remarks>
        /// <param name="userId">The unique identifier of the user whose failed login attempt is being recorded.  This parameter cannot be
        /// null or empty.</param>
        public static void RecordFailedLogin(string userId, AppConfig config)
        {
            Db.WithConnection(conn =>
            {
                // Get current failed attempt info
                int failedLogins = 0;
                DateTime? lastFailed = null;

                using (var getCmd = conn.CreateCommand())
                {
                    getCmd.CommandText = """
                        SELECT failed_logins, last_failed_login
                        FROM users
                        WHERE id = $id AND is_active = 1;
                    """;
                    getCmd.Parameters.AddWithValue("$id", userId);
                    using var reader = getCmd.ExecuteReader();
                    if (!reader.Read())
                        return;

                    failedLogins = reader.GetInt32(0);
                    if (!reader.IsDBNull(1))
                        lastFailed = reader.GetDateTime(1); ;
                }

                var now = DateTime.UtcNow;
                var resetWindow = TimeSpan.FromSeconds(config.SecondsToResetLoginFailures);

                // Reset counter if last failure was too long ago
                if (lastFailed == null || now - lastFailed > resetWindow)
                    failedLogins = 1;
                else
                    failedLogins += 1;

                // Compute lockout, if needed
                DateTime? lockoutUntil = null;
                if (failedLogins >= config.MaxLoginFailures)
                    lockoutUntil = now.AddSeconds(config.FailedPasswordLockoutDuration);

                if (lockoutUntil.HasValue)
                    Log.Warning("User {UserId} has been locked out until {LockoutUntil}", userId, lockoutUntil);

                using var updateCmd = conn.CreateCommand();
                updateCmd.CommandText = """
                UPDATE users
                    SET failed_logins = $fails,
                        last_failed_login = $last,
                        lockout_until = $lock
                    WHERE id = $id;
                """;
                updateCmd.Parameters.AddWithValue("$fails", failedLogins);
                updateCmd.Parameters.AddWithValue("$last", now.ToString("o"));
                updateCmd.Parameters.AddWithValue("$lock", (object?)lockoutUntil?.ToString("o") ?? DBNull.Value);
                updateCmd.Parameters.AddWithValue("$id", userId);
                updateCmd.ExecuteNonQuery();
            });
        }

        /// <summary>
        /// Revokes the active session and refresh tokens for the specified user.
        /// </summary>
        /// <remarks>This method updates the session and refresh token records in the database to mark
        /// them as revoked. It is typically used to log a user out and invalidate their authentication tokens.  The
        /// method requires a valid database connection and assumes that the user ID corresponds to an existing user in
        /// the system. If the user ID does not match any records, no changes will be made.</remarks>
        /// <param name="userId">The unique identifier of the user whose session and refresh tokens should be revoked. This parameter cannot
        /// be null or empty.</param>
        public static void LogoutUser(string userId, string clientIdentifier)
        {
            Db.WithConnection(conn =>
            {
                using var cmd = conn.CreateCommand();
                cmd.CommandText = """
                    UPDATE sessions
                    SET is_revoked = 1
                    WHERE user_id = $uid AND client_identifier = $cid;
                """;
                cmd.Parameters.AddWithValue("$uid", userId);
                cmd.Parameters.AddWithValue("$cid", clientIdentifier);
                cmd.ExecuteNonQuery();

                using var refreshCmd = conn.CreateCommand();
                refreshCmd.CommandText = """
                    UPDATE refresh_tokens
                    SET is_revoked = 1
                    WHERE user_id = $uid AND client_identifier = $cid;
                """;
                refreshCmd.Parameters.AddWithValue("$uid", userId);
                refreshCmd.Parameters.AddWithValue("$cid", clientIdentifier);
                refreshCmd.ExecuteNonQuery();
            });
        }

        /// <summary>
        /// Revokes all active sessions and refresh tokens for the specified user across all clients.
        /// </summary>
        /// <remarks>This method updates the database to mark all sessions and refresh tokens associated
        /// with the  specified user as revoked. Once revoked, the user will be logged out from all clients and  will
        /// need to reauthenticate to access the system.</remarks>
        /// <param name="userId">The unique identifier of the user whose sessions and refresh tokens should be revoked. Cannot be null or
        /// empty.</param>
        public static void LogoutUserAllClients(string userId)
        {
            Db.WithConnection(conn =>
            {
                using var cmd = conn.CreateCommand();
                cmd.CommandText = """
                    UPDATE sessions
                    SET is_revoked = 1
                    WHERE user_id = $uid;
                """;
                cmd.Parameters.AddWithValue("$uid", userId);
                cmd.ExecuteNonQuery();

                using var refreshCmd = conn.CreateCommand();
                refreshCmd.CommandText = """
                    UPDATE refresh_tokens
                    SET is_revoked = 1
                    WHERE user_id = $uid;
                """;
                refreshCmd.Parameters.AddWithValue("$uid", userId);
                refreshCmd.ExecuteNonQuery();
            });
        }
    }
}
