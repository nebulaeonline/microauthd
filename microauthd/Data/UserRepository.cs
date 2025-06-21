using madTypes.Api.Common;
using madTypes.Api.Responses;

using microauthd.Config;
using Microsoft.AspNetCore.DataProtection;
using Serilog;
using System.Reflection.PortableExecutable;
using static microauthd.Tokens.TokenIssuer;

namespace microauthd.Data;

public static class UserRepository
{
    /// <summary>
    /// Creates a new user in the database and retrieves the created user's details.
    /// </summary>
    /// <remarks>This method inserts a new user record into the database and retrieves the user's details
    /// immediately after creation. If the user creation fails (e.g., due to a database constraint violation), the
    /// method returns <see langword="null"/>.</remarks>
    /// <param name="userId">The unique identifier for the user. This value must not be null or empty.</param>
    /// <param name="username">The username of the user. This value must not be null or empty.</param>
    /// <param name="email">The email address of the user. This value must not be null or empty.</param>
    /// <param name="passwordHash">The hashed password of the user. This value must not be null or empty.</param>
    /// <returns>A <see cref="UserObject"/> representing the created user, or <see langword="null"/> if the user could not be
    /// created.</returns>
    public static UserObject? CreateUser(string userId, string username, string email, string passwordHash)
    {
        Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
            INSERT INTO users (id, username, password_hash, email, created_at)
            VALUES ($id, $username, $hash, $email, datetime('now'));
            """;
            cmd.Parameters.AddWithValue("$id", userId);
            cmd.Parameters.AddWithValue("$username", username);
            cmd.Parameters.AddWithValue("$hash", passwordHash);
            cmd.Parameters.AddWithValue("$email", email);
            cmd.ExecuteNonQuery();
        });

        var user = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT id, username, email, created_at, is_active FROM users WHERE id = $id;";
            cmd.Parameters.AddWithValue("$id", userId);

            using var reader = cmd.ExecuteReader();

            if (reader.Read())
            {
                return new UserObject
                {
                    Id = reader.GetString(0),
                    Username = reader.GetString(1),
                    Email = reader.GetString(2),
                    CreatedAt = reader.GetString(3),
                    IsActive = reader.GetInt64(4) == 1
                };
            }
            else
            {
                return null;
            }
        });

        return user;        
    }

    /// <summary>
    /// Determines whether a user with the specified ID exists in the database.
    /// </summary>
    /// <remarks>This method performs a database query to check for the existence of a user with the given ID.
    /// Ensure that the database connection is properly configured before calling this method.</remarks>
    /// <param name="userId">The unique identifier of the user to check. Cannot be null or empty.</param>
    /// <returns>true if a user with the specified ID exists in the database;  otherwise, false. </returns>
    public static bool DoesUserExist(string userId)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT COUNT(*) FROM users WHERE id = $id;";
            cmd.Parameters.AddWithValue("$id", userId);
            return Convert.ToInt32(cmd.ExecuteScalar()) > 0;
        });
    }

    /// <summary>
    /// Determines whether the specified user is active.
    /// </summary>
    /// <remarks>This method queries the database to check the user's active status. Ensure the database
    /// connection is properly configured.</remarks>
    /// <param name="userId">The unique identifier of the user to check. Cannot be null or empty.</param>
    /// <returns><see langword="true"/> if the user is active; otherwise, <see langword="false"/>.</returns>
    public static bool IsUserActive(string userId)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT is_active FROM users WHERE id = $id;";
            cmd.Parameters.AddWithValue("$id", userId);
            return Convert.ToInt64(cmd.ExecuteScalar()) == 1;
        });
    }

    /// <summary>
    /// Checks whether the specified username or email is already in use by another user.
    /// </summary>
    /// <remarks>This method queries the database to determine if any other user, excluding the user with the
    /// specified <paramref name="userId"/>, has the same username or email. It is typically used to enforce uniqueness
    /// constraints during user creation or updates.</remarks>
    /// <param name="userId">The unique identifier of the user to exclude from the conflict check.</param>
    /// <param name="username">The username to check for conflicts.</param>
    /// <param name="email">The email address to check for conflicts.</param>
    /// <returns><see langword="true"/> if the username or email is already in use by another user; otherwise, <see
    /// langword="false"/>.</returns>
    public static bool CheckForUsernameOrEmailConflict(string userId, string username, string email)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT COUNT(*) FROM users
                WHERE (username = $u OR email = $e) AND id != $id;
            """;
            cmd.Parameters.AddWithValue("$u", username);
            cmd.Parameters.AddWithValue("$e", email);
            cmd.Parameters.AddWithValue("$id", userId);
            return Convert.ToInt32(cmd.ExecuteScalar()) > 0;
        });
    }

    /// <summary>
    /// Updates the details of an existing user in the database.
    /// </summary>
    /// <remarks>The method updates the user's information based on the provided <paramref name="updated"/>
    /// object.  The user's ID must correspond to an existing record in the database for the update to
    /// succeed.</remarks>
    /// <param name="updated">An object containing the updated user details, including the user's ID, username, email, and active status.</param>
    /// <returns><see langword="true"/> if the user was successfully updated; otherwise, <see langword="false"/>.</returns>
    public static bool UpdateUser(UserObject updated)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                UPDATE users
                SET username = $u,
                    email = $e,
                    is_active = $a,
                    modified_at = datetime('now')
                WHERE id = $id;
            """;
            cmd.Parameters.AddWithValue("$u", updated.Username);
            cmd.Parameters.AddWithValue("$e", updated.Email);
            cmd.Parameters.AddWithValue("$a", updated.IsActive ? 1 : 0);
            cmd.Parameters.AddWithValue("$id", updated.Id);
            return cmd.ExecuteNonQuery() == 1;
        });
    }

    /// <summary>
    /// Retrieves a user by their unique identifier.
    /// </summary>
    /// <remarks>This method queries the database to retrieve user details based on the provided identifier.
    /// If no user is found with the specified ID, the method returns <see langword="null"/>.</remarks>
    /// <param name="userId">The unique identifier of the user to retrieve. Cannot be null or empty.</param>
    /// <returns>A <see cref="UserObject"/> representing the user if found; otherwise, <see langword="null"/>.</returns>
    public static UserObject? GetUserById(string userId)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT id, username, email, created_at, is_active
                FROM users
                WHERE id = $id;
            """;
            cmd.Parameters.AddWithValue("$id", userId);
            using var reader = cmd.ExecuteReader();
            if (!reader.Read())
                return null;

            return new UserObject
            {
                Id = reader.GetString(0),
                Username = reader.GetString(1),
                Email = reader.GetString(2),
                CreatedAt = reader.GetString(3),
                IsActive = reader.GetBoolean(4)
            };
        });
    }

    /// <summary>
    /// Retrieves a list of all users from the database, ordered by username in ascending order.
    /// </summary>
    /// <remarks>The method queries the database to fetch user information and returns it as a collection of 
    /// <see cref="UserObject"/>. The returned list will be empty if no users are found in the database.</remarks>
    /// <returns>A list of <see cref="UserObject"/> instances, where each object represents a user with their associated details
    /// such as ID, username, email, creation date, and active status.</returns>
    public static List<UserObject> ListUsers()
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT id, username, email, created_at, is_active
                FROM users
                ORDER BY username ASC;
            """;

            using var reader = cmd.ExecuteReader();
            var list = new List<UserObject>();

            while (reader.Read())
            {
                list.Add(new UserObject
                {
                    Id = reader.GetString(0),
                    Username = reader.GetString(1),
                    Email = reader.GetString(2),
                    CreatedAt = reader.GetString(3),
                    IsActive = reader.GetInt64(4) == 1
                });
            }

            return list;
        });
    }

    /// <summary>
    /// Deletes a user from the database based on the specified user ID.
    /// </summary>
    /// <remarks>This method removes the user record associated with the provided <paramref name="userId"/>
    /// from the database. Ensure that the <paramref name="userId"/> corresponds to an existing user to avoid
    /// unnecessary operations.</remarks>
    /// <param name="userId">The unique identifier of the user to delete. Cannot be null or empty.</param>
    /// <returns><see langword="true"/> if the user was successfully deleted; otherwise, <see langword="false"/>.</returns>
    public static bool DeleteUser(string userId)
    {
        var rows = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "DELETE FROM users WHERE id = $id";
            cmd.Parameters.AddWithValue("$id", userId);
            return cmd.ExecuteNonQuery();
        });

        return rows > 0;
    }

    /// <summary>
    /// Revokes all active sessions for the specified user.
    /// </summary>
    /// <remarks>This method updates the session records in the database to mark them as revoked. Once
    /// revoked, the sessions will no longer be valid for authentication or access.</remarks>
    /// <param name="userId">The unique identifier of the user whose sessions should be revoked.  This parameter cannot be null or empty.</param>
    public static void RevokeUserSessions(string userId)
    {
        Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "UPDATE sessions SET is_revoked = 1 WHERE user_id = $uid;";
            cmd.Parameters.AddWithValue("$uid", userId);
            cmd.ExecuteNonQuery();
        });
    }

    /// <summary>
    /// Revokes all active refresh tokens associated with the specified user.
    /// </summary>
    /// <remarks>This method updates the database to mark all refresh tokens for the specified user as
    /// revoked.  Once revoked, the tokens can no longer be used for authentication or obtaining new access
    /// tokens.</remarks>
    /// <param name="userId">The unique identifier of the user whose refresh tokens should be revoked. Cannot be null or empty.</param>
    public static void RevokeUserRefreshTokens(string userId)
    {
        Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "UPDATE refresh_tokens SET is_revoked = 1 WHERE user_id = $uid;";
            cmd.Parameters.AddWithValue("$uid", userId);
            cmd.ExecuteNonQuery();
        });
    }

    /// <summary>
    /// Deactivates a user by setting their status to inactive in the database.
    /// </summary>
    /// <remarks>This method updates the user's status in the database to inactive only if the user is
    /// currently active. If the user is already inactive or does not exist, the method returns <see
    /// langword="false"/>.</remarks>
    /// <param name="userId">The unique identifier of the user to deactivate. Cannot be null or empty.</param>
    /// <returns><see langword="true"/> if the user was successfully deactivated; otherwise, <see langword="false"/>.</returns>
    public static bool DeactivateUser(string userId)
    {
        Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "UPDATE users SET is_active = 0 WHERE id = $id AND is_active = 1;";
            cmd.Parameters.AddWithValue("$id", userId);
            return cmd.ExecuteNonQuery();
        });

        return true;
    }

    /// <summary>
    /// Reactivates a user account by setting the user's status to active.
    /// </summary>
    /// <remarks>This method updates the user's status in the database to active only if the user is currently
    /// inactive. If the user is already active or the user ID does not exist, the method returns <see
    /// langword="false"/>.</remarks>
    /// <param name="userId">The unique identifier of the user to reactivate. Cannot be null or empty.</param>
    /// <returns><see langword="true"/> if the user was successfully reactivated; otherwise, <see langword="false"/>.</returns>
    public static bool ReactivateUser(string userId)
    {
        var affected = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "UPDATE users SET is_active = 1 WHERE id = $id AND is_active = 0;";
            cmd.Parameters.AddWithValue("$id", userId);
            return cmd.ExecuteNonQuery();
        });

        return affected > 0;
    }

    /// <summary>
    /// Resets the password for an active user by updating the password hash in the database.
    /// </summary>
    /// <remarks>This method updates the password hash for a user in the database only if the user is active. 
    /// The operation is performed as a single database transaction.</remarks>
    /// <param name="userId">The unique identifier of the user whose password is being reset. Must not be null or empty.</param>
    /// <param name="newPasswordHash">The new hashed password to be set for the user. Must not be null or empty.</param>
    /// <returns><see langword="true"/> if the password was successfully updated; otherwise, <see langword="false"/> if the user
    /// does not exist, is inactive, or the update failed.</returns>
    public static bool ResetUserPassword(string userId, string newPasswordHash)
    {
        var affected = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                UPDATE users
                SET password_hash = $hash, modified_at = datetime('now')
                WHERE id = $id AND is_active = 1;
            """;
            cmd.Parameters.AddWithValue("$id", userId);
            cmd.Parameters.AddWithValue("$hash", newPasswordHash);
            return cmd.ExecuteNonQuery();
        });

        return affected > 0;
    }

    /// <summary>
    /// Writes a session record to the database using the provided token information, application configuration, and
    /// client identifier.
    /// </summary>
    /// <remarks>This method inserts a new session record into the database. The session is marked as active
    /// (not revoked) upon creation. Ensure that the provided <paramref name="token"/> and <paramref
    /// name="clientIdent"/> are valid and that the database connection is properly configured in <paramref
    /// name="config"/>.</remarks>
    /// <param name="token">The token information containing session details such as the token ID, user ID, issued time, and expiration
    /// time.</param>
    /// <param name="config">The application configuration used to establish the database connection.</param>
    /// <param name="clientIdent">A unique identifier for the client associated with the session.</param>
    public static void WriteSessionToDb(TokenInfo token, string clientIdent)
    {
        Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                    INSERT INTO sessions (id, user_id, client_identifier, token, issued_at, expires_at, is_revoked)
                    VALUES ($id, $uid, $cid, $token, $iat, $exp, 0);
                """;
            cmd.Parameters.AddWithValue("$id", token.Jti);
            cmd.Parameters.AddWithValue("$uid", token.UserId);
            cmd.Parameters.AddWithValue("$cid", clientIdent);
            cmd.Parameters.AddWithValue("$token", token.Token);
            cmd.Parameters.AddWithValue("$iat", token.IssuedAt.ToString("o"));
            cmd.Parameters.AddWithValue("$exp", token.ExpiresAt.ToString("o"));
            cmd.ExecuteNonQuery();
        });
    }

    /// <summary>
    /// Retrieves a list of all sessions from the database, ordered by their issuance date in descending order.
    /// </summary>
    /// <remarks>This method queries the database to fetch session information and returns it as a collection
    /// of <see cref="SessionResponse"/>. The sessions are ordered by their issuance date, with the most recently issued
    /// sessions appearing first.</remarks>
    /// <returns>A list of <see cref="SessionResponse"/> objects representing the sessions. Each session includes details such as
    /// its unique identifier, associated user ID, issuance and expiration timestamps, revocation status, and token
    /// usage.</returns>
    public static List<SessionResponse> ListSessions()
    {
        var sessions = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                    SELECT id, user_id, issued_at, expires_at, is_revoked, token_use
                    FROM sessions
                    ORDER BY issued_at DESC;
                """;

            using var reader = cmd.ExecuteReader();
            var list = new List<SessionResponse>();

            while (reader.Read())
            {
                list.Add(new SessionResponse
                {
                    Id = reader.GetString(0),
                    UserId = reader.GetString(1),
                    IssuedAt = DateTime.Parse(reader.GetString(2)),
                    ExpiresAt = DateTime.Parse(reader.GetString(3)),
                    IsRevoked = reader.GetInt64(4) == 1,
                    TokenUse = reader.GetString(5)
                });
            }

            return list;
        });

        return sessions;
    }

    /// <summary>
    /// Retrieves a session by its unique identifier (JTI).
    /// </summary>
    /// <remarks>This method queries the database to retrieve session details based on the provided JTI. If no
    /// session matches the specified JTI, the method returns <see langword="null"/>.</remarks>
    /// <param name="jti">The unique identifier of the session to retrieve. This value must not be null or empty.</param>
    /// <returns>A <see cref="SessionResponse"/> object representing the session if found; otherwise, <see langword="null"/>.</returns>
    public static SessionResponse? GetSessionById(string jti)
    {
        var session = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT id, user_id, client_identifier, issued_at, expires_at, is_revoked, token_use
                FROM sessions
                WHERE id = $jti;
            """;
            cmd.Parameters.AddWithValue("$jti", jti);

            using var reader = cmd.ExecuteReader();
            if (!reader.Read())
                return null;

            return new SessionResponse
            {
                Id = reader.GetString(0),
                UserId = reader.GetString(1),
                ClientIdentifier = reader.GetString(2),
                IssuedAt = DateTime.Parse(reader.GetString(3)),
                ExpiresAt = DateTime.Parse(reader.GetString(4)),
                IsRevoked = reader.GetInt64(5) == 1,
                TokenUse = reader.GetString(6)
            };
        });

        return session;
    }

    /// <summary>
    /// Retrieves a list of session records associated with the specified user ID.
    /// </summary>
    /// <remarks>This method queries the database to retrieve session information for the specified user. Each
    /// session includes details such as its ID, issuance and expiration timestamps,  revocation status, and token
    /// usage.</remarks>
    /// <param name="userId">The unique identifier of the user whose sessions are to be retrieved.  This parameter cannot be null or empty.</param>
    /// <returns>A list of <see cref="SessionResponse"/> objects representing the user's sessions. The list is ordered by the
    /// session's issuance date in descending order. If no sessions are found for the specified user ID, an empty list
    /// is returned.</returns>
    public static List<SessionResponse> GetSessionsByUserId(string userId)
    {
        var sessions = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                    SELECT id, user_id, issued_at, expires_at, is_revoked, token_use
                    FROM sessions
                    WHERE user_id = $uid
                    ORDER BY issued_at DESC;
                """;
            cmd.Parameters.AddWithValue("$uid", userId);

            using var reader = cmd.ExecuteReader();
            var list = new List<SessionResponse>();

            while (reader.Read())
            {
                list.Add(new SessionResponse
                {
                    Id = reader.GetString(0),
                    UserId = reader.GetString(1),
                    IssuedAt = DateTime.Parse(reader.GetString(2)),
                    ExpiresAt = DateTime.Parse(reader.GetString(3)),
                    IsRevoked = reader.GetInt64(4) == 1,
                    TokenUse = reader.GetString(5)
                });
            }

            return list;
        });

        return sessions;
    }

    /// <summary>
    /// Retrieves a list of refresh tokens associated with the specified user ID.
    /// </summary>
    /// <remarks>This method queries the database to retrieve refresh tokens for the specified user. Each
    /// token includes details such as its ID, associated session ID, issuance and expiration dates, and whether it has
    /// been revoked.</remarks>
    /// <param name="userId">The unique identifier of the user whose refresh tokens are to be retrieved. This parameter cannot be null or
    /// empty.</param>
    /// <returns>A list of <see cref="RefreshTokenResponse"/> objects representing the refresh tokens associated with the
    /// specified user. The list is ordered by the issuance date in descending order. If no tokens are found for the
    /// user, an empty list is returned.</returns>
    public static List<RefreshTokenResponse> GetRefreshTokensByUserId(string userId)
    {
        var tokens = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT id, user_id, session_id, issued_at, expires_at, is_revoked
                FROM refresh_tokens
                WHERE user_id = $uid
                ORDER BY issued_at DESC;
            """;
            cmd.Parameters.AddWithValue("$uid", userId);

            using var reader = cmd.ExecuteReader();
            var list = new List<RefreshTokenResponse>();

            while (reader.Read())
            {
                list.Add(new RefreshTokenResponse
                {
                    Id = reader.GetString(0),
                    UserId = reader.GetString(1),
                    SessionId = reader.GetString(2),
                    IssuedAt = DateTime.Parse(reader.GetString(3)),
                    ExpiresAt = DateTime.Parse(reader.GetString(4)),
                    IsRevoked = reader.GetInt64(5) == 1
                });
            }

            return list;
        });

        return tokens;
    }

    /// <summary>
    /// Revokes a session identified by its unique token (JTI).
    /// </summary>
    /// <remarks>This method checks the session's state before attempting to revoke it. If the session is
    /// already revoked or expired,  the operation will not proceed, and the response will indicate the
    /// reason.</remarks>
    /// <param name="jti">The unique identifier (JTI) of the session to revoke. This value must not be null or empty.</param>
    /// <returns>A tuple containing two values: <list type="bullet"> <item> <description><see langword="true"/> if the session
    /// was successfully revoked; otherwise, <see langword="false"/>.</description> </item> <item> <description>A
    /// response message providing details about the operation's outcome.</description> </item> </returns></returns>
    public static (bool revoked, string response, string userId) RevokeSessionById(string jti)
    {
        var session = GetSessionById(jti);

        if (session is null)
            return (false, $"Session {jti} not found.", string.Empty);

        var userId = session.UserId;
        var expiresAt = session.ExpiresAt;
        var isRevoked = session.IsRevoked;

        var revoke_response = Db.WithConnection(conn =>
        {
            if (isRevoked)
            {
                return (false, $"Session {jti} has already been revoked.", userId);                
            }

            if (expiresAt < DateTime.UtcNow)
            {
                return (false, $"Session {jti} has already expired.", userId);
            }

            using var updateCmd = conn.CreateCommand();
            updateCmd.CommandText = "UPDATE sessions SET is_revoked = 1 WHERE id = $jti;";
            updateCmd.Parameters.AddWithValue("$jti", jti);
            updateCmd.ExecuteNonQuery();

            return (true, $"Session {jti} has been revoked successfully.", userId);        
        });

        return revoke_response;
    }

    /// <summary>
    /// Deletes session records from the database based on specified criteria.
    /// </summary>
    /// <remarks>This method performs a bulk deletion of session records based on the specified criteria. If
    /// neither  <paramref name="purgeExpired"/> nor <paramref name="purgeRevoked"/> is <see langword="true"/>, no
    /// records will  be deleted, and the method will return a success value of <see langword="true"/> with a purged
    /// count of 0.</remarks>
    /// <param name="olderThan">A <see cref="TimeSpan"/> representing the age threshold for expired sessions. Sessions older than this value 
    /// will be considered for deletion if <paramref name="purgeExpired"/> is <see langword="true"/>.</param>
    /// <param name="purgeExpired">A <see langword="bool"/> indicating whether to delete sessions that have expired. If <see langword="true"/>, 
    /// sessions with an expiration date older than the current time minus <paramref name="olderThan"/> will be purged.</param>
    /// <param name="purgeRevoked">A <see langword="bool"/> indicating whether to delete sessions that have been explicitly revoked. If  <see
    /// langword="true"/>, sessions marked as revoked will be purged.</param>
    /// <returns>A tuple containing two values: <list type="bullet"> <item> <description> <see langword="success"/>: A <see
    /// langword="bool"/> indicating whether the operation completed successfully. </description> </item> <item>
    /// <description> <see langword="purged"/>: An <see langword="int"/> representing the number of session records that
    /// were deleted. </description> </item> </list></returns>
    public static (bool success, int purged) PurgeSessions(TimeSpan olderThan, bool purgeExpired, bool purgeRevoked)
    {
        var conditions = new List<string>();
        if (purgeExpired)
            conditions.Add("expires_at < datetime('now', $cutoff)");
        if (purgeRevoked)
            conditions.Add("is_revoked = 1");

        if (conditions.Count == 0)
            return (true, 0);

        var whereClause = string.Join(" OR ", conditions);

        var purged = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = $"DELETE FROM sessions WHERE {whereClause};";

            if (purgeExpired)
                cmd.Parameters.AddWithValue("$cutoff", $"-{(int)olderThan.TotalSeconds} seconds");

            return cmd.ExecuteNonQuery();
        });

        return (true, purged);
    }

    /// <summary>
    /// Stores a refresh token in the database for a specific user and session.
    /// </summary>
    /// <remarks>This method inserts a new refresh token record into the database. The refresh token is
    /// associated with a user, session, and client identifier, and includes security hashes for validation. The token
    /// is marked as active upon creation.</remarks>
    /// <param name="id">The unique identifier for the refresh token.</param>
    /// <param name="userId">The unique identifier of the user associated with the refresh token.</param>
    /// <param name="sessionId">The unique identifier of the session associated with the refresh token.</param>
    /// <param name="clientIdent">A string representing the client identifier, typically used to identify the device or application.</param>
    /// <param name="hash">The hashed value of the refresh token for secure storage.</param>
    /// <param name="sha256Hash">The SHA-256 hash of the refresh token for additional security.</param>
    /// <param name="expires">The expiration date and time of the refresh token in UTC.</param>
    public static void StoreRefreshToken(string id, string userId, string sessionId, string clientIdent, string hash, string sha256Hash, DateTime expires)
    {
        Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                    INSERT INTO refresh_tokens (
                        id, user_id, session_id, client_identifier, refresh_token_hash,
                        refresh_token_sha256, issued_at, expires_at, is_revoked
                    )
                    VALUES ($id, $userId, $sessionId, $cid, $hash, $sha256, $issuedAt, $expiresAt, 0);
                """;
            cmd.Parameters.AddWithValue("$id", id);
            cmd.Parameters.AddWithValue("$userId", userId);
            cmd.Parameters.AddWithValue("$sessionId", sessionId);
            cmd.Parameters.AddWithValue("$cid", clientIdent);
            cmd.Parameters.AddWithValue("$hash", hash);
            cmd.Parameters.AddWithValue("$sha256", sha256Hash);
            cmd.Parameters.AddWithValue("$issuedAt", DateTime.UtcNow.ToString("o"));
            cmd.Parameters.AddWithValue("$expiresAt", expires.ToString("o"));
            cmd.ExecuteNonQuery();
        });
    }

    /// <summary>
    /// Retrieves a list of refresh tokens from the database.
    /// </summary>
    /// <remarks>This method queries the database for all refresh tokens, including their associated user IDs,
    /// session IDs, issuance and expiration timestamps, and revocation status. The results are ordered by the issuance
    /// date in descending order, with the most recently issued tokens appearing first.</remarks>
    /// <returns>A list of <see cref="RefreshTokenResponse"/> objects, where each object represents a refresh token and its
    /// associated metadata. The list will be empty if no refresh tokens are found.</returns>
    public static List<RefreshTokenResponse> ListRefreshTokens()
    {
        var tokens = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                    SELECT id, user_id, session_id, issued_at, expires_at, is_revoked
                    FROM refresh_tokens
                    ORDER BY issued_at DESC;
                """;

            using var reader = cmd.ExecuteReader();
            var list = new List<RefreshTokenResponse>();

            while (reader.Read())
            {
                list.Add(new RefreshTokenResponse
                {
                    Id = reader.GetString(0),
                    UserId = reader.GetString(1),
                    SessionId = reader.GetString(2),
                    IssuedAt = DateTime.Parse(reader.GetString(3)),
                    ExpiresAt = DateTime.Parse(reader.GetString(4)),
                    IsRevoked = reader.GetInt64(5) == 1
                });
            }

            return list;
        });

        return tokens;
    }

    /// <summary>
    /// Retrieves a refresh token by its unique identifier.
    /// </summary>
    /// <remarks>This method queries the database to retrieve information about a refresh token, including its
    /// associated user, session, issuance and expiration times, and revocation status. Ensure that the provided
    /// <paramref name="tokenId"/> corresponds to a valid token in the database.</remarks>
    /// <param name="tokenId">The unique identifier of the refresh token to retrieve. This value cannot be null or empty.</param>
    /// <returns>A <see cref="RefreshTokenResponse"/> object containing details of the refresh token if found; otherwise, <see
    /// langword="null"/> if no token exists with the specified identifier.</returns>
    public static RefreshTokenResponse? GetRefreshTokenById(string tokenId)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT id, user_id, session_id, issued_at, expires_at, is_revoked
                FROM refresh_tokens
                WHERE id = $id;
            """;
            cmd.Parameters.AddWithValue("$id", tokenId);

            using var reader = cmd.ExecuteReader();
            if (!reader.Read())
                return null;

            return new RefreshTokenResponse
            {
                Id = reader.GetString(0),
                UserId = reader.GetString(1),
                SessionId = reader.GetString(2),
                IssuedAt = DateTime.Parse(reader.GetString(3)),
                ExpiresAt = DateTime.Parse(reader.GetString(4)),
                IsRevoked = reader.GetInt64(5) == 1
            };
        });
    }

    /// <summary>
    /// Deletes refresh tokens from the database based on specified conditions.
    /// </summary>
    /// <remarks>At least one of <paramref name="purgeExpired"/> or <paramref name="purgeRevoked"/> must be
    /// <see langword="true"/> for the method to perform any deletions. If neither condition is specified, the method
    /// will return a success result with zero tokens purged.</remarks>
    /// <param name="olderThan">A <see cref="TimeSpan"/> representing the age threshold for tokens to be purged. Tokens older than this duration
    /// will be considered for deletion if <paramref name="purgeExpired"/> is <see langword="true"/>.</param>
    /// <param name="purgeExpired">A <see langword="bool"/> indicating whether expired tokens should be purged. If <see langword="true"/>, tokens
    /// with an expiration date earlier than the cutoff will be deleted.</param>
    /// <param name="purgeRevoked">A <see langword="bool"/> indicating whether revoked tokens should be purged. If <see langword="true"/>, tokens
    /// marked as revoked will be deleted.</param>
    /// <returns>A tuple containing: <list type="bullet"> <item> <term><see langword="success"/></term> <description>A <see
    /// langword="bool"/> indicating whether the operation completed successfully.</description> </item> <item>
    /// <term><see langword="purged"/></term> <description>An <see cref="int"/> representing the number of tokens that
    /// were deleted.</description> </item> </list></returns>
    public static (bool success, int purged) PurgeRefreshTokens(TimeSpan olderThan, bool purgeExpired, bool purgeRevoked)
    {
        var conditions = new List<string>();
        if (purgeExpired)
            conditions.Add("expires_at < datetime('now', $cutoff)");
        if (purgeRevoked)
            conditions.Add("is_revoked = 1");

        if (conditions.Count == 0)
            return (true, 0);

        var whereClause = string.Join(" OR ", conditions);

        var purged = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = $"DELETE FROM refresh_tokens WHERE {whereClause};";

            if (purgeExpired)
                cmd.Parameters.AddWithValue("$cutoff", $"-{(int)olderThan.TotalSeconds} seconds");

            return cmd.ExecuteNonQuery();
        });

        return (true, purged);
    }

    /// <summary>
    /// Retrieves the username of an active user based on their unique identifier.
    /// </summary>
    /// <remarks>This method queries the database to find the username of a user whose account is active. If
    /// no matching user is found or the user is inactive, the method returns <see langword="null"/>.</remarks>
    /// <param name="userId">The unique identifier of the user. This value cannot be null or empty.</param>
    /// <returns>The username of the active user if found; otherwise, <see langword="null"/>.</returns>
    public static string? GetUsernameById(string userId)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT username FROM users WHERE id = $id AND is_active = 1";
            cmd.Parameters.AddWithValue("$id", userId);
            using var reader = cmd.ExecuteReader();
            if (!reader.Read())
                return null;

            return reader.GetString(0); // username
        });
    }

    /// <summary>
    /// Updates the OTP secret for the specified user in the database.
    /// </summary>
    /// <remarks>This method updates the OTP secret for a user in the database only if the user is active.
    /// Ensure that <paramref name="userId"/> corresponds to a valid and active user.</remarks>
    /// <param name="userId">The unique identifier of the user whose OTP secret is being updated. Must correspond to an active user.</param>
    /// <param name="otpSecret">The new OTP secret to associate with the user. Cannot be null or empty.</param>
    public static void StoreOtpSecret(string userId, string otpSecret)
    {
        Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                UPDATE users
                SET otp_secret = $secret
                WHERE id = $id AND is_active = 1;
            """;
            cmd.Parameters.AddWithValue("$secret", otpSecret);
            cmd.Parameters.AddWithValue("$id", userId);
            cmd.ExecuteNonQuery();
        });
    }

    /// <summary>
    /// Retrieves the OTP secret associated with the specified user ID.
    /// </summary>
    /// <remarks>This method queries the database to retrieve the OTP secret for the user with the given ID.
    /// The user must be active for the OTP secret to be returned.</remarks>
    /// <param name="userId">The unique identifier of the user whose OTP secret is to be retrieved. Must not be <see langword="null"/> or
    /// empty.</param>
    /// <returns>The OTP secret as a string if the user exists and is active; otherwise, <see langword="null"/>.</returns>
    public static string? GetOtpSecretByUserId(string userId)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT otp_secret FROM users WHERE id = $id AND is_active = 1";
            cmd.Parameters.AddWithValue("$id", userId);
            using var reader = cmd.ExecuteReader();
            return reader.Read() ? reader.GetString(0) : null;
        });
    }

    /// <summary>
    /// Enables OTP (One-Time Password) authentication for the specified user.
    /// </summary>
    /// <remarks>This method updates the database to enable OTP authentication for the user with the specified
    /// ID. Ensure that the database connection is properly configured and accessible.</remarks>
    /// <param name="userId">The unique identifier of the user for whom OTP authentication should be enabled. This parameter cannot be null
    /// or empty.</param>
    /// <returns>The number of rows affected by the operation. Typically, this will be 1 if the user exists and the update is
    /// successful, or 0 if no matching user is found.</returns>
    public static int EnableOtpForUserId(string userId)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "UPDATE users SET totp_enabled = 1 WHERE id = $id";
            cmd.Parameters.AddWithValue("$id", userId);
            return cmd.ExecuteNonQuery();
        });
    }

    /// <summary>
    /// Disables OTP (One-Time Password) functionality for the specified user.
    /// </summary>
    /// <remarks>This method updates the user's record in the database to disable OTP functionality by
    /// clearing the OTP secret and marking OTP as disabled. The operation only affects users who are active.</remarks>
    /// <param name="userId">The unique identifier of the user for whom OTP functionality should be disabled. Must not be <see
    /// langword="null"/> or empty.</param>
    /// <returns>The number of rows affected by the operation. Returns 0 if no active user with the specified ID exists.</returns>
    public static int DisableOtpForUserId(string userId)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                UPDATE users
                SET totp_enabled = 0,
                    totp_secret = NULL
                WHERE id = $id AND is_active = 1;
            """;
            cmd.Parameters.AddWithValue("$id", userId);
            return cmd.ExecuteNonQuery();
        });
    }
}
