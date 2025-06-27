using madTypes.Api.Common;
using madTypes.Api.Responses;

using microauthd.Config;
using Microsoft.AspNetCore.DataProtection;
using Serilog;
using System.CommandLine.Parsing;
using System.Globalization;
using System.Reflection.PortableExecutable;
using static microauthd.Tokens.TokenIssuer;

namespace microauthd.Data;

public class RefreshToken
{
    public string Id { get; init; } = string.Empty;
    public string UserId { get; init; } = string.Empty;
    public string SessionId { get; init; } = string.Empty;
    public DateTime ExpiresAt { get; init; }
    public bool IsRevoked { get; init; }
    public string ClientIdentifier { get; init; } = string.Empty;
}

public static class UserStore
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
                    CreatedAt = reader.GetDateTime(3),
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
    public static bool DoesUserIdExist(string userId)
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
    /// Determines whether a specified username exists in the database.
    /// </summary>
    /// <remarks>This method queries the database to check for the presence of the specified username. It
    /// performs a case-sensitive comparison and returns a boolean indicating the result.</remarks>
    /// <param name="username">The username to check for existence. Cannot be null or empty.</param>
    /// <returns><see langword="true"/> if the username exists in the database; otherwise, <see langword="false"/>. </returns>
    public static bool DoesUsernameExist(string username)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT COUNT(*) FROM users WHERE username = $username;";
            cmd.Parameters.AddWithValue("$username", username);
            return Convert.ToInt32(cmd.ExecuteScalar()) > 0;
        });
    }

    /// <summary>
    /// Determines whether the specified email address exists in the database.
    /// </summary>
    /// <remarks>This method queries the database to check for the presence of the specified email address.
    /// Ensure that the database connection is properly configured and accessible before calling this method.</remarks>
    /// <param name="email">The email address to check for existence. Cannot be null or empty.</param>
    /// <returns><see langword="true"/> if the email address exists in the database; otherwise, <see langword="false"/>.</returns>
    public static bool DoesEmailExist(string email)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT COUNT(*) FROM users WHERE email = $email;";
            cmd.Parameters.AddWithValue("$email", email);
            return Convert.ToInt32(cmd.ExecuteScalar()) > 0;
        });
    }

    /// <summary>
    /// Retrieves the user ID associated with the specified username.
    /// </summary>
    /// <remarks>This method queries the database to find the user ID corresponding to the given username.  If
    /// no matching username is found, the method returns <see langword="null"/>.</remarks>
    /// <param name="username">The username of the user whose ID is to be retrieved. Cannot be null or empty.</param>
    /// <returns>The user ID as a string if the username exists in the database; otherwise, <see langword="null"/>.</returns>
    public static string? GetUserIdByUsername(string username)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT id FROM users WHERE username = $username LIMIT 1;";
            cmd.Parameters.AddWithValue("$username", username);

            var result = cmd.ExecuteScalar();
            return result == null ? null : Convert.ToString(result);
        });
    }

    /// <summary>
    /// Determines whether the specified user is active.
    /// </summary>
    /// <remarks>This method queries the database to check the user's active status. Ensure the database
    /// connection is properly configured.</remarks>
    /// <param name="userId">The unique identifier of the user to check. Cannot be null or empty.</param>
    /// <returns><see langword="true"/> if the user is active; otherwise, <see langword="false"/>.</returns>
    public static bool IsUserIdActive(string userId)
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
                    lockout_until = $l,
                    modified_at = datetime('now')
                WHERE id = $id;
            """;
            cmd.Parameters.AddWithValue("$u", updated.Username);
            cmd.Parameters.AddWithValue("$e", updated.Email);
            cmd.Parameters.AddWithValue("$a", updated.IsActive ? 1 : 0);
            cmd.Parameters.AddWithValue("$l", updated.LockoutUntil.HasValue ? updated.LockoutUntil.Value.ToString("o") : DBNull.Value);
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
                SELECT id, username, email, created_at, is_active, lockout_until
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
                CreatedAt = reader.GetDateTime(3),
                IsActive = reader.GetBoolean(4),
                LockoutUntil = reader.IsDBNull(5) ? null : reader.GetDateTime(5)
            };
        });
    }

    /// <summary>
    /// Retrieves the password hash for the specified user.
    /// </summary>
    /// <remarks>This method queries the database to retrieve the password hash associated with the given user
    /// ID. Ensure that the provided <paramref name="userId"/> corresponds to a valid user in the database.</remarks>
    /// <param name="userId">The unique identifier of the user whose password hash is to be retrieved. Cannot be null or empty.</param>
    /// <returns>The password hash of the user as a string. Returns an empty string if the user does not exist or the password
    /// hash is not set.</returns>
    public static string GetUserPasswordHash(string userId)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT password_hash FROM users WHERE id = $id;";
            cmd.Parameters.AddWithValue("$id", userId);
            var result = cmd.ExecuteScalar();
            return result?.ToString() ?? string.Empty;
        });
    }


    /// <summary>
    /// Retrieves the lockout expiration date and time for the specified user.
    /// </summary>
    /// <remarks>This method queries the database to retrieve the lockout expiration timestamp for the
    /// specified user. Ensure that the database connection is properly configured and accessible.</remarks>
    /// <param name="userId">The unique identifier of the user whose lockout information is being retrieved. Cannot be null or empty.</param>
    /// <returns>A <see cref="DateTime"/> representing the date and time until the user is locked out.  Returns <see
    /// cref="DateTime.MinValue"/> if the user is not locked out or if no lockout information is found.</returns>
    public static DateTime GetUserLockoutUntil(string userId)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT lockout_until FROM users WHERE id = $id;";
            cmd.Parameters.AddWithValue("$id", userId);
            var result = cmd.ExecuteScalar();
            return result is DateTime dt ? dt : DateTime.MinValue;
        });
    }

    /// <summary>
    /// Retrieves a user by their username.
    /// </summary>
    /// <remarks>This method queries the database to find a user with the specified username. If no matching
    /// user exists, the method returns <see langword="null"/>. The returned <see cref="UserObject"/> contains details
    /// such as the user's ID, username, email, creation date, and active status.</remarks>
    /// <param name="username">The username of the user to retrieve. This parameter cannot be null or empty.</param>
    /// <returns>A <see cref="UserObject"/> representing the user with the specified username, or <see langword="null"/> if no
    /// user is found.</returns>
    public static UserObject? GetUserByUsername(string username)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT id, username, email, created_at, is_active, lockout_until
                FROM users
                WHERE username = $username;
            """;
            cmd.Parameters.AddWithValue("$username", username);
            using var reader = cmd.ExecuteReader();
            if (!reader.Read())
                return null;

            return new UserObject
            {
                Id = reader.GetString(0),
                Username = reader.GetString(1),
                Email = reader.GetString(2),
                CreatedAt = reader.GetDateTime(3),
                IsActive = reader.GetBoolean(4),
                LockoutUntil = reader.IsDBNull(5) ? null : reader.GetDateTime(5)
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
    public static List<UserObject> ListUsers(int offset = 0, int limit = 50)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT id, username, email, is_active, created_at, lockout_until
                FROM users
                WHERE is_active = 1
                ORDER BY username
                LIMIT $limit OFFSET $offset
            """;
            cmd.Parameters.AddWithValue("$limit", limit);
            cmd.Parameters.AddWithValue("$offset", offset);

            using var reader = cmd.ExecuteReader();
            var results = new List<UserObject>();
            while (reader.Read())
            {
                results.Add(new UserObject
                {
                    Id = reader.GetGuid(0).ToString(),
                    Username = reader.GetString(1),
                    Email = reader.GetString(2),
                    IsActive = reader.GetBoolean(3),
                    CreatedAt = reader.GetDateTime(4),
                    LockoutUntil = reader.IsDBNull(5) ? null : reader.GetDateTime(5)
                });
            }

            return results;
        });
    }

    /// <summary>
    /// Retrieves a paginated list of inactive users from the database.
    /// </summary>
    /// <remarks>This method queries the database for users who are marked as inactive and returns their
    /// details. The results are ordered by username in ascending order. Use the <paramref name="offset"/> and 
    /// <paramref name="limit"/> parameters to control pagination.</remarks>
    /// <param name="offset">The zero-based index of the first record to retrieve. Must be non-negative.</param>
    /// <param name="limit">The maximum number of records to retrieve. Must be greater than zero. Defaults to 50.</param>
    /// <returns>A list of <see cref="UserObject"/> instances representing inactive users.  The list will be empty if no inactive
    /// users are found.</returns>
    public static List<UserObject> ListInactiveUsers(int offset = 0, int limit = 50)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT id, username, email, is_active, created_at
                FROM users
                WHERE is_active = 0
                ORDER BY username
                LIMIT $limit OFFSET $offset
            """;
            cmd.Parameters.AddWithValue("$limit", limit);
            cmd.Parameters.AddWithValue("$offset", offset);

            using var reader = cmd.ExecuteReader();
            var results = new List<UserObject>();
            while (reader.Read())
            {
                results.Add(new UserObject
                {
                    Id = reader.GetGuid(0).ToString(),
                    Username = reader.GetString(1),
                    Email = reader.GetString(2),
                    IsActive = reader.GetBoolean(3),
                    CreatedAt = reader.GetDateTime(4)
                });
            }

            return results;
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
    public static bool RevokeUserSessions(string userId)
    {
        Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "UPDATE sessions SET is_revoked = 1 WHERE user_id = $uid;";
            cmd.Parameters.AddWithValue("$uid", userId);
            cmd.ExecuteNonQuery();
        });

        return true;
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
    /// Revokes a refresh token by marking it as revoked in the database.
    /// </summary>
    /// <remarks>This method updates the database to mark the specified refresh token as revoked.  Once
    /// revoked, the token can no longer be used for authentication or token renewal.</remarks>
    /// <param name="tokenId">The unique identifier of the refresh token to revoke. This value cannot be null or empty.</param>
    public static void RevokeRefreshToken(string tokenId)
    {
        Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "UPDATE refresh_tokens SET is_revoked = 1 WHERE id = $id;";
            cmd.Parameters.AddWithValue("$id", tokenId);
            cmd.ExecuteNonQuery();
        });
    }

    /// <summary>
    /// Retrieves a refresh token from the database using its SHA-256 hash.
    /// </summary>
    /// <remarks>This method queries the database for a refresh token that matches the provided SHA-256 hash.
    /// If no matching token is found, the method returns <see langword="null"/>.</remarks>
    /// <param name="tokenSha256Hash">The SHA-256 hash of the refresh token to retrieve. This value must be a non-null, non-empty string.</param>
    /// <returns>A <see cref="RefreshToken"/> object representing the refresh token if found; otherwise, <see langword="null"/>.</returns>
    public static RefreshToken? GetRefreshTokenBySha256Hash(string tokenSha256Hash)
    {
        var token = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT id, user_id, session_id, expires_at, is_revoked, client_identifier
                FROM refresh_tokens
                WHERE refresh_token_sha256 = $sha256;
            """;
            cmd.Parameters.AddWithValue("$sha256", tokenSha256Hash);

            using var reader = cmd.ExecuteReader();
            if (!reader.Read()) return null;

            return new RefreshToken
            {
                Id = reader.GetString(0),
                UserId = reader.GetString(1),
                SessionId = reader.GetString(2),
                ExpiresAt = DateTime.Parse(reader.GetString(3),
                    CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.AssumeUniversal |
                        System.Globalization.DateTimeStyles.AdjustToUniversal),
                IsRevoked = reader.GetInt64(4) == 1,
                ClientIdentifier = reader.GetString(5)
            };
        });

        return token;
    }

    /// <summary>
    /// Retrieves a paginated list of refresh tokens along with associated user information.
    /// </summary>
    /// <remarks>This method queries the database to retrieve refresh tokens and their associated user
    /// information. The results are paginated using the <paramref name="offset"/> and <paramref name="limit"/>
    /// parameters.</remarks>
    /// <param name="offset">The zero-based index of the first refresh token to retrieve. Must be non-negative.</param>
    /// <param name="limit">The maximum number of refresh tokens to retrieve. Must be greater than zero.</param>
    /// <returns>A list of <see cref="RefreshTokenResponse"/> objects, each containing details about a refresh token and its
    /// associated user. The list is ordered by the issuance date of the refresh tokens in descending order.</returns>
    public static List<RefreshTokenResponse> ListRefreshTokensWithUsername(int offset = 0, int limit = 50)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT
                    rt.id,
                    rt.user_id,
                    u.username,
                    rt.session_id,
                    rt.client_identifier,
                    rt.issued_at,
                    rt.expires_at,
                    rt.is_revoked
                FROM refresh_tokens rt
                JOIN users u ON rt.user_id = u.id
                ORDER BY rt.issued_at DESC
                LIMIT $limit OFFSET $offset;
            """;
            cmd.Parameters.AddWithValue("$limit", limit);
            cmd.Parameters.AddWithValue("$offset", offset);

            using var reader = cmd.ExecuteReader();
            var results = new List<RefreshTokenResponse>();

            while (reader.Read())
            {
                results.Add(new RefreshTokenResponse
                {
                    Id = reader.GetString(0),
                    UserId = reader.GetString(1),
                    Username = reader.GetString(2),
                    SessionId = reader.GetString(3),
                    ClientIdentifier = reader.GetString(4),
                    IssuedAt = reader.GetDateTime(5),
                    ExpiresAt = reader.GetDateTime(6),
                    IsRevoked = reader.GetBoolean(7)
                });
            }

            return results;
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
                    INSERT INTO sessions (id, user_id, client_identifier, token, issued_at, expires_at, is_revoked, token_use)
                    VALUES ($id, $uid, $cid, $token, $iat, $exp, 0, $use);
                """;
            cmd.Parameters.AddWithValue("$id", token.Jti);
            cmd.Parameters.AddWithValue("$uid", token.UserId);
            cmd.Parameters.AddWithValue("$cid", clientIdent);
            cmd.Parameters.AddWithValue("$token", token.Token);
            cmd.Parameters.AddWithValue("$iat", token.IssuedAt.ToString("o"));
            cmd.Parameters.AddWithValue("$exp", token.ExpiresAt.ToString("o"));
            cmd.Parameters.AddWithValue("$use", token.TokenUse);
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
                    IssuedAt = DateTime.Parse(reader.GetString(2),
                        CultureInfo.InvariantCulture,
                        System.Globalization.DateTimeStyles.AssumeUniversal |
                            System.Globalization.DateTimeStyles.AdjustToUniversal),
                    ExpiresAt = DateTime.Parse(reader.GetString(3),
                        CultureInfo.InvariantCulture,
                        System.Globalization.DateTimeStyles.AssumeUniversal |
                            System.Globalization.DateTimeStyles.AdjustToUniversal),
                    IsRevoked = reader.GetInt64(4) == 1,
                    TokenUse = reader.GetString(5)
                });
            }

            return list;
        });

        return sessions;
    }

    /// <summary>
    /// Retrieves a paginated list of session records from the database.
    /// </summary>
    /// <remarks>The sessions are ordered by their issuance time in descending order. This method is useful
    /// for retrieving session data for auditing, monitoring, or user activity tracking.</remarks>
    /// <param name="offset">The zero-based index of the first session record to retrieve. Must be non-negative.</param>
    /// <param name="limit">The maximum number of session records to retrieve. Must be greater than zero.</param>
    /// <returns>A list of <see cref="SessionResponse"/> objects representing session records. The list will be empty if no
    /// sessions match the specified criteria.</returns>
    public static List<SessionResponse> ListSessions(int offset = 0, int limit = 50)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT
                    s.id,
                    s.user_id,
                    u.username,
                    s.client_identifier,
                    s.issued_at,
                    s.expires_at,
                    s.is_revoked,
                    s.token_use
                FROM sessions s
                LEFT JOIN users u ON s.user_id = u.id
                ORDER BY s.issued_at DESC
                LIMIT $limit OFFSET $offset;
            """;
            cmd.Parameters.AddWithValue("$limit", limit);
            cmd.Parameters.AddWithValue("$offset", offset);

            using var reader = cmd.ExecuteReader();
            var sessions = new List<SessionResponse>();

            while (reader.Read())
            {
                sessions.Add(new SessionResponse
                {
                    Id = reader.GetString(0),
                    UserId = reader.GetString(1),
                    Username = reader.GetString(2),
                    ClientIdentifier = reader.GetString(3),
                    IssuedAt = reader.GetDateTime(4),
                    ExpiresAt = reader.GetDateTime(5),
                    IsRevoked = reader.GetBoolean(6),
                    TokenUse = reader.GetString(7)
                });
            }

            return sessions;
        });
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
                IssuedAt = DateTime.Parse(reader.GetString(3),
                    CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.AssumeUniversal |
                        System.Globalization.DateTimeStyles.AdjustToUniversal),
                ExpiresAt = DateTime.Parse(reader.GetString(4),
                    CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.AssumeUniversal |
                        System.Globalization.DateTimeStyles.AdjustToUniversal),
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
                    IssuedAt = DateTime.Parse(reader.GetString(2),
                        CultureInfo.InvariantCulture,
                        System.Globalization.DateTimeStyles.AssumeUniversal |
                            System.Globalization.DateTimeStyles.AdjustToUniversal),
                    ExpiresAt = DateTime.Parse(reader.GetString(3),
                        CultureInfo.InvariantCulture,
                        System.Globalization.DateTimeStyles.AssumeUniversal |
                            System.Globalization.DateTimeStyles.AdjustToUniversal),
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
                    IssuedAt = DateTime.Parse(reader.GetString(3),
                        CultureInfo.InvariantCulture,
                        System.Globalization.DateTimeStyles.AssumeUniversal |
                            System.Globalization.DateTimeStyles.AdjustToUniversal),
                    ExpiresAt = DateTime.Parse(reader.GetString(4),
                        CultureInfo.InvariantCulture,
                        System.Globalization.DateTimeStyles.AssumeUniversal |
                            System.Globalization.DateTimeStyles.AdjustToUniversal),
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
    /// Determines whether a token, identified by its JTI (JSON Web Token ID), is revoked.
    /// </summary>
    /// <remarks>This method queries a database to check if the specified JTI exists in the denylist and is
    /// still valid. Ensure that the database connection and schema are properly configured before calling this
    /// method.</remarks>
    /// <param name="jti">The unique identifier of the token to check. This value cannot be null or empty.</param>
    /// <returns><see langword="true"/> if the token is found in the denylist and has not expired; otherwise, <see
    /// langword="false"/>.</returns>
    public static bool IsTokenRevokedJti(string jti)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT 1 FROM jti_denylist WHERE jti = $jti AND expires_at > datetime('now')";
            cmd.Parameters.AddWithValue("$jti", jti);
            using var reader = cmd.ExecuteReader();
            return reader.Read();
        });
    }

    /// <summary>
    /// Determines whether the specified token has been revoked.
    /// </summary>
    /// <remarks>This method queries the database to check the revocation status of the token. A token is
    /// considered revoked if the corresponding database entry indicates it.</remarks>
    /// <param name="token">The token to check for revocation. Cannot be null or empty.</param>
    /// <returns><see langword="true"/> if the token has been revoked; otherwise, <see langword="false"/>.</returns>
    public static bool IsTokenRevoked(string token)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT is_revoked FROM sessions WHERE token = $token";
            cmd.Parameters.AddWithValue("$token", token);
            var result = cmd.ExecuteScalar();
            return result is long val && val == 1;
        });
    }

    /// <summary>
    /// Revokes the specified token by marking it as invalid in the database.
    /// </summary>
    /// <remarks>This method updates the database to mark the token as revoked. Ensure the token provided is
    /// valid and corresponds to an active session.</remarks>
    /// <param name="token">The token to be revoked. Cannot be null or empty.</param>
    /// <returns>The number of rows affected in the database. Returns 0 if no matching token was found.</returns>
    public static int RevokeToken(string token)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "UPDATE sessions SET is_revoked = 1 WHERE token = $token";
            cmd.Parameters.AddWithValue("$token", token);
            return cmd.ExecuteNonQuery(); // affected rows
        });
    }

    /// <summary>
    /// Adds a token identifier (JTI) to the blacklist, preventing its future use for authentication.
    /// </summary>
    /// <remarks>This method stores the JTI and its expiration timestamp in a persistent denylist. If the JTI
    /// already exists in the denylist, the operation is ignored.</remarks>
    /// <param name="jti">The unique identifier of the token to be blacklisted. This value cannot be null or empty.</param>
    /// <param name="expiresAt">The expiration date and time of the token. This determines when the blacklist entry becomes irrelevant.</param>
    public static void AddTokenToBlacklist(string jti, DateTime expiresAt)
    {
        Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                INSERT OR IGNORE INTO jti_denylist (jti, expires_at)
                VALUES ($jti, $exp)
            """;
            cmd.Parameters.AddWithValue("$jti", jti);
            cmd.Parameters.AddWithValue("$exp", expiresAt.ToString("yyyy-MM-dd HH:mm:ss"));
            cmd.ExecuteNonQuery();
        });
    }

    /// <summary>
    /// Deletes session records from the database based on specified criteria.
    /// </summary>
    /// <remarks>This method performs a bulk deletion of session records based on the specified criteria. At
    /// least one of <paramref name="purgeExpired"/> or <paramref name="purgeRevoked"/> must be <see langword="true"/>
    /// for any records to be purged.</remarks>
    /// <param name="olderThanUtc">The cutoff date and time in UTC. Sessions older than this value may be purged if the relevant criteria are
    /// enabled.</param>
    /// <param name="purgeExpired">A value indicating whether expired sessions should be purged. If <see langword="true"/>, sessions with an
    /// expiration date earlier than <paramref name="olderThanUtc"/> will be deleted.</param>
    /// <param name="purgeRevoked">A value indicating whether revoked sessions should be purged. If <see langword="true"/>, sessions marked as
    /// revoked will be deleted.</param>
    /// <returns>A tuple containing the result of the operation: <list type="bullet"> <item> <term><c>success</c></term>
    /// <description><see langword="true"/> if the operation completed successfully; otherwise, <see
    /// langword="false"/>.</description> </item> <item> <term><c>purged</c></term> <description>The number of session
    /// records that were deleted.</description> </item> </list></returns>
    public static (bool success, int purged) PurgeSessions(DateTime olderThanUtc, bool purgeExpired, bool purgeRevoked)
    {
        var conditions = new List<string>();

        if (purgeExpired)
            conditions.Add("strftime('%s', expires_at) < strftime('%s', $cutoff)");
        if (purgeRevoked)
            conditions.Add("(is_revoked = 1 AND strftime('%s', expires_at) < strftime('%s', $cutoff))");

        if (conditions.Count == 0)
            return (true, 0); // nothing to do

        var whereClause = string.Join(" OR ", conditions);

        var purged = Db.WithConnection(conn =>
        {
            using var txn = conn.BeginTransaction();

            using var cmd = conn.CreateCommand();
            cmd.Transaction = txn;
            cmd.CommandText = $"DELETE FROM sessions WHERE {whereClause};";
            cmd.Parameters.AddWithValue("$cutoff", olderThanUtc);
            var result = cmd.ExecuteNonQuery();
            txn.Commit();
            return result;
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
    public static void StoreRefreshToken(string id, string userId, string sessionId, string clientIdent, string sha256Hash, DateTime expires)
    {
        Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                    INSERT INTO refresh_tokens (
                        id, user_id, session_id, client_identifier,
                        refresh_token_sha256, issued_at, expires_at, is_revoked
                    )
                    VALUES ($id, $userId, $sessionId, $cid, $sha256, $issuedAt, $expiresAt, 0);
                """;
            cmd.Parameters.AddWithValue("$id", id);
            cmd.Parameters.AddWithValue("$userId", userId);
            cmd.Parameters.AddWithValue("$sessionId", sessionId);
            cmd.Parameters.AddWithValue("$cid", clientIdent);
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
                    IssuedAt = DateTime.Parse(reader.GetString(3),
                        CultureInfo.InvariantCulture,
                        System.Globalization.DateTimeStyles.AssumeUniversal |
                            System.Globalization.DateTimeStyles.AdjustToUniversal),
                    ExpiresAt = DateTime.Parse(reader.GetString(4),
                        CultureInfo.InvariantCulture,
                        System.Globalization.DateTimeStyles.AssumeUniversal |
                            System.Globalization.DateTimeStyles.AdjustToUniversal),
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
                IssuedAt = DateTime.Parse(reader.GetString(3),
                        CultureInfo.InvariantCulture,
                        System.Globalization.DateTimeStyles.AssumeUniversal |
                            System.Globalization.DateTimeStyles.AdjustToUniversal),
                ExpiresAt = DateTime.Parse(reader.GetString(4),
                        CultureInfo.InvariantCulture,
                        System.Globalization.DateTimeStyles.AssumeUniversal |
                            System.Globalization.DateTimeStyles.AdjustToUniversal),
                IsRevoked = reader.GetInt64(5) == 1
            };
        });
    }

    /// <summary>
    /// Deletes refresh tokens from the database based on specified criteria.
    /// </summary>
    /// <remarks>This method allows selective purging of refresh tokens based on expiration and revocation
    /// status. If neither <paramref name="purgeExpired"/> nor <paramref name="purgeRevoked"/> is <see
    /// langword="true"/>, no tokens will be purged.</remarks>
    /// <param name="olderThanUtc">A <see cref="DateTime"/> value representing the cutoff date and time in UTC. Tokens created before this date may
    /// be purged, depending on the specified criteria.</param>
    /// <param name="purgeExpired">A <see langword="true"/> value indicates that expired tokens should be purged; otherwise, <see
    /// langword="false"/>.</param>
    /// <param name="purgeRevoked">A <see langword="true"/> value indicates that revoked tokens should be purged; otherwise, <see
    /// langword="false"/>.</param>
    /// <returns>A tuple containing two values: <list type="bullet"> <item> <description><see langword="success"/>: A <see
    /// langword="true"/> value indicates the operation completed successfully.</description> </item> <item>
    /// <description><see langword="purged"/>: An <see cref="int"/> representing the number of tokens that were
    /// deleted.</description> </item> </list></returns>
    public static (bool success, int purged) PurgeRefreshTokens(DateTime olderThanUtc, bool purgeExpired, bool purgeRevoked)
{
    var conditions = new List<string>();

    if (purgeExpired)
        conditions.Add("strftime('%s', expires_at) < strftime('%s', $cutoff)");
    if (purgeRevoked)
        conditions.Add("(is_revoked = 1 AND strftime('%s', expires_at) < strftime('%s', $cutoff))");

    if (conditions.Count == 0)
        return (true, 0); // nothing to do

    var whereClause = string.Join(" OR ", conditions);

    var purged = Db.WithConnection(conn =>
    {
        using var txn = conn.BeginTransaction();

        using var cmd = conn.CreateCommand();
        cmd.Transaction = txn;
        cmd.CommandText = $"DELETE FROM refresh_tokens WHERE {whereClause};";
        cmd.Parameters.AddWithValue("$cutoff", olderThanUtc);
        var result = cmd.ExecuteNonQuery();
        txn.Commit();
        return result;
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
    public static void StoreTotpSecret(string userId, string otpSecret)
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
    public static string? GetTotpSecretByUserId(string userId)
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
    public static int EnableTotpForUserId(string userId)
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
    public static int DisableTotpForUserId(string userId)
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

    /// <summary>
    /// Determines whether Time-based One-Time Password (TOTP) authentication is enabled for the specified user.
    /// </summary>
    /// <remarks>This method queries the database to check the TOTP status for the user. Ensure the database
    /// connection is properly configured and accessible.</remarks>
    /// <param name="userId">The unique identifier of the user. Cannot be null or empty.</param>
    /// <returns><see langword="true"/> if TOTP authentication is enabled for the user and the user is active; otherwise, <see
    /// langword="false"/>.</returns>
    public static bool IsTotpEnabledForUserId(string userId)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT totp_enabled FROM users WHERE id = $id AND is_active = 1";
            cmd.Parameters.AddWithValue("$id", userId);
            using var reader = cmd.ExecuteReader();
            return reader.Read() && reader.GetBoolean(0);
        });
    }

    /// <summary>
    /// Sets the lockout expiration date for a user, preventing them from accessing the system until the specified time.
    /// </summary>
    /// <remarks>This method updates the lockout expiration date in the database for the specified user. If
    /// <paramref name="until"/> is <see langword="null"/>, the lockout is cleared.</remarks>
    /// <param name="userId">The unique identifier of the user whose lockout status is being updated. Cannot be null or empty.</param>
    /// <param name="until">The date and time until which the user is locked out, in UTC.  Specify <see langword="null"/> to remove the
    /// lockout and allow immediate access.</param>
    public static void SetUserLockoutUntil(string userId, DateTime? until)
    {
        Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
            UPDATE users
            SET lockout_until = $until
            WHERE id = $id;
        """;
            cmd.Parameters.AddWithValue("$id", userId);
            cmd.Parameters.AddWithValue("$until", until.HasValue ? until.Value.ToString("o") : DBNull.Value);
            cmd.ExecuteNonQuery();
        });
    }

    /// <summary>
    /// Retrieves the count of active users from the database.
    /// </summary>
    /// <remarks>This method queries the database to count the number of users marked as active.  It returns
    /// the total number of active users as an integer.  Ensure that the database connection is properly configured
    /// before calling this method.</remarks>
    /// <returns>The total number of active users in the database.</returns>
    public static int GetUserCount()
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT COUNT(*) FROM users WHERE is_active = 1;";
            return Convert.ToInt32(cmd.ExecuteScalar());
        });
    }

    /// <summary>
    /// Retrieves the count of inactive users from the database.
    /// </summary>
    /// <remarks>This method executes a SQL query to count users where the "is_active" field is set to 0.
    /// Ensure the database connection is properly configured before calling this method.</remarks>
    /// <returns>The total number of users marked as inactive in the database.</returns>
    public static int GetInactiveUserCount()
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT COUNT(*) FROM users WHERE is_active = 0;";
            return Convert.ToInt32(cmd.ExecuteScalar());
        });
    }

    /// <summary>
    /// Retrieves the total number of user sessions from the database.
    /// </summary>
    /// <remarks>This method executes a query against the database to count the entries in the "sessions"
    /// table. Ensure that the database connection is properly configured and accessible before calling this
    /// method.</remarks>
    /// <returns>The total count of active user sessions. Returns 0 if no sessions are found.</returns>
    public static int GetUserSessionCount()
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT COUNT(*) FROM sessions;";
            return Convert.ToInt32(cmd.ExecuteScalar());
        });
    }

    /// <summary>
    /// Retrieves the count of active user sessions from the database.
    /// </summary>
    /// <remarks>An active session is defined as a session that has not been revoked and has an expiration
    /// time later than the current time.</remarks>
    /// <returns>The total number of active user sessions. Returns 0 if no active sessions are found.</returns>
    public static int GetActiveUserSessionCount()
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT COUNT(*) FROM sessions WHERE is_revoked = 0 AND strftime('%s', expires_at) > strftime('%s', 'now');";
            return Convert.ToInt32(cmd.ExecuteScalar());
        });
    }

    /// <summary>
    /// Retrieves the count of active refresh tokens.
    /// </summary>
    /// <remarks>A refresh token is considered active if it has not been revoked and its expiration time is in
    /// the future. This method queries the database to calculate the count of such tokens.</remarks>
    /// <returns>The total number of active refresh tokens.</returns>
    public static int GetActiveRefreshTokenCount()
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT COUNT(*) FROM refresh_tokens WHERE is_revoked = 0 AND strftime('%s', expires_at) > strftime('%s', 'now');";
            return Convert.ToInt32(cmd.ExecuteScalar());
        });
    }

    /// <summary>
    /// Retrieves the total number of refresh tokens stored in the database.
    /// </summary>
    /// <remarks>This method executes a SQL query to count the rows in the "refresh_tokens" table. Ensure that
    /// the database connection is properly configured before calling this method.</remarks>
    /// <returns>The total count of refresh tokens as an integer. Returns 0 if no refresh tokens are found.</returns>
    public static int GetRefreshTokenCount()
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT COUNT(*) FROM refresh_tokens;";
            return Convert.ToInt32(cmd.ExecuteScalar());
        });
    }
}
