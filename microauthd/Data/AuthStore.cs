using madTypes.Api.Common;
using microauthd.Config;
using Serilog;
using System.Globalization;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;

namespace microauthd.Data
{
    /// <summary>
    /// Stores a PKCE (Proof Key for Code Exchange) code into the database
    /// </summary>
    public static class AuthStore
    {
        public static void StorePkceCode(PkceCode pkce)
        {
            Db.WithConnection(conn =>
            {
                using var cmd = conn.CreateCommand();
                cmd.CommandText = """
                    INSERT INTO pkce_codes 
                    (code, client_identifier, redirect_uri, code_challenge, code_challenge_method, expires_at, is_used, user_id, jti, nonce, scope)
                    VALUES
                    ($code, $client_identifier, $redirect_uri, $challenge, $method, $expires, $used, $user_id, $jti, $nonce, $scope);
                """;

                cmd.Parameters.AddWithValue("$code", pkce.Code);
                cmd.Parameters.AddWithValue("$client_identifier", pkce.ClientIdentifier.Trim());
                cmd.Parameters.AddWithValue("$redirect_uri", pkce.RedirectUri.Trim());
                cmd.Parameters.AddWithValue("$challenge", pkce.CodeChallenge.Trim());
                cmd.Parameters.AddWithValue("$method", pkce.CodeChallengeMethod.Trim());
                cmd.Parameters.AddWithValue("$expires", pkce.ExpiresAt.ToString("o")); // ISO 8601
                cmd.Parameters.AddWithValue("$used", pkce.IsUsed ? 1 : 0);
                cmd.Parameters.AddWithValue("$user_id", pkce.UserId.Trim());
                cmd.Parameters.AddWithValue("$jti", (object?)pkce.Jti?.Trim() ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$nonce", (object?)pkce.Nonce?.Trim() ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$scope", pkce.Scope?.Trim());

                cmd.ExecuteNonQuery();
            });
        }

        /// <summary>
        /// Retrieves a PKCE code from the database based on the provided code identifier.
        /// </summary>
        /// <remarks>This method queries the database for a PKCE code matching the specified identifier.
        /// If no matching code is found, the method returns <see langword="null"/>. The returned <see cref="PkceCode"/>
        /// object includes information such as the client ID, redirect URI, code challenge, code challenge method,
        /// expiration time, and usage status.</remarks>
        /// <param name="code">The unique identifier of the PKCE code to retrieve. This value must not be null or empty.</param>
        /// <returns>A <see cref="PkceCode"/> object containing the details of the PKCE code if found; otherwise, <see
        /// langword="null"/>.</returns>
        public static PkceCode? GetPkceCode(string code)
        {
            return Db.WithConnection(conn =>
            {
                using var cmd = conn.CreateCommand();
                cmd.CommandText = """
                    SELECT code, client_identifier, redirect_uri, code_challenge, code_challenge_method,
                           expires_at, is_used, user_id, jti, nonce, scope
                    FROM pkce_codes
                    WHERE code = $code
                    LIMIT 1;
                """;
                cmd.Parameters.AddWithValue("$code", code);

                using var reader = cmd.ExecuteReader();
                if (!reader.Read()) return null;

                return new PkceCode
                {
                    Code = reader.GetString(0).Trim(),
                    ClientIdentifier = reader.GetString(1).Trim(),
                    RedirectUri = reader.GetString(2).Trim(),
                    CodeChallenge = reader.GetString(3).Trim(),
                    CodeChallengeMethod = reader.GetString(4).Trim(),
                    ExpiresAt = DateTime.Parse(
                        reader.GetString(5), 
                        CultureInfo.InvariantCulture, 
                        System.Globalization.DateTimeStyles.AssumeUniversal | 
                            System.Globalization.DateTimeStyles.AdjustToUniversal), // ISO 8601
                    IsUsed = reader.GetBoolean(6),
                    UserId = reader.GetString(7).Trim(),
                    Jti = reader.IsDBNull(8) ? null : reader.GetString(8).Trim(),
                    Nonce = reader.IsDBNull(9) ? null : reader.GetString(9).Trim(),
                    Scope = reader.IsDBNull(10) ? null : reader.GetString(10).Trim()
                };
            });
        }

        /// <summary>
        /// Associates a user with a PKCE code in the database.
        /// </summary>
        /// <remarks>This method updates the database to associate the specified user with the given PKCE
        /// code. The operation will only succeed if the code exists and has not already been used.</remarks>
        /// <param name="code">The PKCE code to be updated. This must correspond to an existing, unused code in the database.</param>
        /// <param name="userId">The unique identifier of the user to associate with the PKCE code.</param>
        public static void AttachUserIdToPkceCode(string code, string userId)
        {
            Db.WithConnection(conn =>
            {
                using var cmd = conn.CreateCommand();
                cmd.CommandText = """
                    UPDATE pkce_codes
                    SET user_id = $userId
                    WHERE code = $code AND is_used = 0;
                """;
                cmd.Parameters.AddWithValue("$code", code.Trim());
                cmd.Parameters.AddWithValue("$userId", userId.Trim());
                cmd.ExecuteNonQuery();
            });
        }

        /// <summary>
        /// Associates a JSON Web Token ID (JTI) with a PKCE code in the database.
        /// </summary>
        /// <remarks>This method updates the database to attach the specified JTI to the given PKCE code,
        /// provided the code has not already been used. The operation is performed within a database
        /// connection.</remarks>
        /// <param name="code">The PKCE code to which the JTI will be attached. This value must correspond to an existing, unused code in
        /// the database.</param>
        /// <param name="jti">The JSON Web Token ID (JTI) to associate with the specified PKCE code. This value is typically used to track
        /// and validate token usage.</param>
        public static void AttachJtiToPkceCode(string code, string jti)
        {
            Db.WithConnection(conn =>
            {
                using var cmd = conn.CreateCommand();
                cmd.CommandText = """
                    UPDATE pkce_codes
                    SET jti = $jti
                    WHERE code = $code AND is_used = 0;
                """;
                cmd.Parameters.AddWithValue("$code", code.Trim());
                cmd.Parameters.AddWithValue("$jti", jti.Trim());
                cmd.ExecuteNonQuery();
            });
        }

        /// <summary>
        /// Marks the specified PKCE code as used in the database.
        /// </summary>
        /// <remarks>This method updates the database to indicate that the provided PKCE code has been
        /// used. Ensure that the <paramref name="code"/> corresponds to a valid entry in the database.</remarks>
        /// <param name="code">The PKCE code to mark as used. This value must not be null or empty.</param>
        public static void MarkPkceCodeAsUsed(string code)
        {
            Db.WithConnection(conn =>
            {
                using var cmd = conn.CreateCommand();
                cmd.CommandText = """
                    UPDATE pkce_codes SET is_used = 1 WHERE code = $code;
                """;
                cmd.Parameters.AddWithValue("$code", code.Trim());
                cmd.ExecuteNonQuery();
            });
        }

        /// <summary>
        /// Validates whether the specified redirect URI is registered for the given client identifier.
        /// </summary>
        /// <remarks>This method checks the database to determine if the provided redirect URI is
        /// associated with the client identified by <paramref name="clientIdentifier"/>. The validation ensures that
        /// the redirect URI is authorized for the client before proceeding with operations such as authentication or
        /// authorization.</remarks>
        /// <param name="clientIdentifier">The unique identifier of the client application. Cannot be null or empty.</param>
        /// <param name="redirectUri">The redirect URI to validate. Cannot be null or empty.</param>
        /// <returns><see langword="true"/> if the redirect URI is registered for the specified client identifier; otherwise,
        /// <see langword="false"/>.</returns>
        public static bool IsRedirectUriValid(string clientIdentifier, string redirectUri)
        {
            return Db.WithConnection(conn =>
            {
                using var cmd = conn.CreateCommand();
                cmd.CommandText = """
                    SELECT 1 FROM redirect_uris
                    WHERE uri = $uri AND client_id = (
                        SELECT id FROM clients WHERE client_identifier = $clientId LIMIT 1
                    )
                    LIMIT 1;
                """;
                cmd.Parameters.AddWithValue("$uri", redirectUri.Trim());
                cmd.Parameters.AddWithValue("$clientId", clientIdentifier.Trim());

                using var reader = cmd.ExecuteReader();
                return reader.Read(); // true if found
            });
        }

        /// <summary>
        /// Inserts a nonce value into the database for a specified user and client.
        /// </summary>
        /// <remarks>This method stores a nonce value in the database for OpenID Connect (OIDC)
        /// operations.  The nonce is used to associate a client request with a user session and to mitigate replay
        /// attacks.</remarks>
        /// <param name="userId">The unique identifier of the user associated with the nonce. Cannot be <see langword="null"/> or empty.</param>
        /// <param name="clientId">The unique identifier of the client associated with the nonce. Cannot be <see langword="null"/> or empty.</param>
        /// <param name="nonce">The nonce value to be stored. Cannot be <see langword="null"/> or empty.</param>
        /// <returns><see langword="true"/> if the nonce was successfully inserted into the database; otherwise, <see
        /// langword="false"/>.</returns>
        public static bool InsertNonce(string userId, string clientId, string nonce)
        {
            return Db.WithConnection(conn =>
            {
                var id = Guid.NewGuid().ToString();

                using var cmd = conn.CreateCommand();
                cmd.CommandText = """
                    INSERT INTO oidc_nonces (id, user_id, client_id, nonce) VALUES
                    ($id, $uid, $cid, $nonce);
                """;
                cmd.Parameters.AddWithValue("$id", id);
                cmd.Parameters.AddWithValue("$uid", userId.Trim());
                cmd.Parameters.AddWithValue("$cid", clientId.Trim());
                cmd.Parameters.AddWithValue("$nonce", nonce.Trim());

                var result = cmd.ExecuteNonQuery();
                return result > 0; // Returns true if the insert was successful
            });
        }

        /// <summary>
        /// Determines whether a specific nonce exists for the given user and client in the database.
        /// </summary>
        /// <remarks>This method queries the database to verify the existence of a nonce associated with 
        /// the specified user and client. It is typically used in OpenID Connect (OIDC) flows  to prevent replay
        /// attacks by ensuring the nonce has not been reused.</remarks>
        /// <param name="userId">The unique identifier of the user.</param>
        /// <param name="clientId">The unique identifier of the client application.</param>
        /// <param name="nonce">The nonce value to check for existence.</param>
        /// <returns><see langword="true"/> if the specified nonce exists for the given user and client;  otherwise, <see
        /// langword="false"/>.</returns>
        public static bool DoesNonceExistForUserAndClient(string userId, string clientId, string nonce)
        {
            return Db.WithConnection(conn =>
            {
                using var cmd = conn.CreateCommand();
                cmd.CommandText = """
                    SELECT 1 FROM oidc_nonces
                    WHERE user_id = $uid AND client_id = $cid AND nonce = $nonce
                    LIMIT 1;
                """;
                cmd.Parameters.AddWithValue("$uid", userId.Trim());
                cmd.Parameters.AddWithValue("$cid", clientId.Trim());
                cmd.Parameters.AddWithValue("$nonce", nonce.Trim());
                using var reader = cmd.ExecuteReader();
                return reader.Read(); // true if found
            });
        }

        /// <summary>
        /// Deletes all nonces from the database that were created before the specified date and time.
        /// </summary>
        /// <remarks>This method removes expired nonces from the database to maintain data integrity and
        /// reduce storage usage. The operation is performed as a single database command.</remarks>
        /// <param name="olderThanDateTime">The cutoff date and time. Nonces created before this value will be deleted.</param>
        /// <returns><see langword="true"/> if one or more nonces were deleted; otherwise, <see langword="false"/>.</returns>
        public static bool PurgeNonces(DateTime olderThanDateTime)
        {
            return Db.WithConnection(conn =>
            {
                using var cmd = conn.CreateCommand();
                cmd.CommandText = """
                    DELETE FROM oidc_nonces
                    WHERE strftime('%Y-%m-%d %H:%M:%S', created_at) < $olderThan;
                """;
                cmd.Parameters.AddWithValue("$olderThan", olderThanDateTime.ToString("yyyy-MM-dd HH:mm:ss"));
                var result = cmd.ExecuteNonQuery();
                return result > 0; // Returns true if any rows were deleted
            });
        }

        /// <summary>
        /// Retrieves a list of claims associated with the specified user.
        /// </summary>
        /// <remarks>This method retrieves claims from multiple sources, including user information, 
        /// roles, and scopes. Claims are deduplicated where applicable.  The caller is responsible for ensuring that
        /// the <paramref name="userId"/>  is valid and corresponds to an existing user.</remarks>
        /// <param name="userId">The unique identifier of the user for whom claims are to be retrieved.  This value cannot be null or empty.</param>
        /// <returns>A list of <see cref="Claim"/> objects representing the user's claims.  The list will include standard claims
        /// such as the user's ID, username, email,  email verification status, roles, and scopes. If the user does not
        /// exist,  an empty list is returned.</returns>
        public static List<Claim> GetUserClaims(string userId)
        {
            var claims = new List<Claim>();

            var user = UserStore.GetUserById(userId);

            if (user is not null)
            {
                // Add standard claims

                // Preferred username
                if (!string.IsNullOrEmpty(user.Username))
                {
                    claims.Add(new Claim("preferred_username", user.Username));
                    claims.Add(new Claim("username", user.Username));
                }

                // User Id
                claims.Add(new Claim(JwtRegisteredClaimNames.Sub, user.Id));

                // Email
                if (!string.IsNullOrEmpty(user.Email))
                    claims.Add(new Claim(JwtRegisteredClaimNames.Email, user.Email));

                // Email verification status
                claims.Add(new Claim(JwtRegisteredClaimNames.EmailVerified, user.EmailVerified ? "true" : "false"));
            }

            foreach (var role in RoleStore.GetUserRoles(userId).Distinct())
                claims.Add(new Claim("role", role));

            foreach (var scope in ScopeStore.GetUserScopes(userId).Distinct())
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
                        lastFailed = reader.GetDateTime(1).ToUniversalTime();
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
        /// Retrieves the number of failed login attempts for the specified user.
        /// </summary>
        /// <remarks>This method queries the database to retrieve the failed login count for the user.
        /// Ensure that the user ID provided corresponds to an active user in the system.</remarks>
        /// <param name="userId">The unique identifier of the user whose failed login attempts are to be retrieved. Must not be <see
        /// langword="null"/> or empty.</param>
        /// <returns>The number of failed login attempts for the user. Returns 0 if the user does not exist or is inactive.</returns>
        public static int GetFailedLoginAttempts(string userId)
        {
            return Db.WithConnection(conn =>
            {
                using var cmd = conn.CreateCommand();
                cmd.CommandText = """
                    SELECT failed_logins
                    FROM users
                    WHERE id = $id AND is_active = 1;
                """;
                cmd.Parameters.AddWithValue("$id", userId);
                using var reader = cmd.ExecuteReader();

                if (!reader.Read())
                    return 0; // User not found or inactive

                return reader.GetInt32(0);
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
