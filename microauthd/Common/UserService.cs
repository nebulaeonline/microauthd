using madTypes.Api.Requests;
using madTypes.Api.Responses;
using microauthd.Config;
using Microsoft.Data.Sqlite;
using nebulae.dotArgon2;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using static microauthd.Tokens.TokenIssuer;
using static nebulae.dotArgon2.Argon2;

namespace microauthd.Common;

public static class UserService
{
    /// <summary>
    /// Retrieves a summary of the identity information for the specified user.
    /// </summary>
    /// <param name="user">The <see cref="ClaimsPrincipal"/> representing the authenticated user.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="WhoamiResponse"/> with a greeting message if the user is
    /// authenticated; otherwise, an unauthorized result.</returns>
    public static ApiResult<WhoamiResponse> GetIdentitySummary(ClaimsPrincipal user)
    {
        var userId = user.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;

        if (string.IsNullOrWhiteSpace(userId))
            return ApiResult<WhoamiResponse>.Forbidden();

        return ApiResult<WhoamiResponse>.Ok(new WhoamiResponse($"Hello, {userId}"));
    }

    /// <summary>
    /// Creates a new user in the database with the specified username, email, and password.
    /// </summary>
    /// <remarks>This method generates a unique identifier for the user and securely hashes the
    /// provided password using the hashing algorithm specified in the <paramref name="config" />. The user is then
    /// added to the database with the current timestamp.</remarks>
    /// <param name="username">The username for the new user. Must be unique and non-empty.</param>
    /// <param name="email">The email address for the new user. Must be a valid email format and unique.</param>
    /// <param name="password">The password for the new user. This will be securely hashed before storage.</param>
    /// <param name="config">The application configuration used to determine password hashing settings.</param>
    public static ApiResult<MessageResponse> CreateUser(
        string username,
        string email,
        string password,
        AppConfig config,
        string? ip = null,
        string? ua = null
)
    {
        if (string.IsNullOrWhiteSpace(username) ||
            string.IsNullOrWhiteSpace(email) ||
            string.IsNullOrWhiteSpace(password))
        {
            return ApiResult<MessageResponse>.Fail("Username, email, and password are required", 400);
        }

        var userId = Guid.NewGuid().ToString();
        var passwordHash = AuthService.HashPassword(password, config);

        try
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
        }
        catch
        {
            return ApiResult<MessageResponse>.Fail("User creation failed (maybe duplicate username?)", 400);
        }

        AuditLogger.AuditLog(
            userId: userId,
            action: "user_created",
            target: username,
            ipAddress: ip,
            userAgent: ua
        );

        return ApiResult<MessageResponse>.Ok(
            new MessageResponse($"User '{username}' created"), 200
        );
    }

    /// <summary>
    /// Creates a new user with the specified details, scoped to the permissions of the acting user.
    /// </summary>
    /// <remarks>This method performs the following steps: <list type="bullet"> <item>Validates that the
    /// acting user has the required scope to provision users.</item> <item>Ensures that the username, email, and
    /// password in the request are not null or empty.</item> <item>Generates a unique user ID and hashes the password
    /// using the provided configuration.</item> <item>Attempts to insert the new user into the database. If the
    /// operation fails (e.g., due to a duplicate username or email), the method returns a failure result.</item>
    /// <item>Logs the operation in the audit log, including the acting user's ID, the action performed, and optional
    /// metadata such as IP address and user agent.</item> </list></remarks>
    /// <param name="actingUser">The user performing the operation. Must have the <see cref="SystemScopes.ProvisionUsers"/> scope.</param>
    /// <param name="request">The details of the user to be created, including username, email, and password. All fields are required.</param>
    /// <param name="config">The application configuration used for password hashing and other settings.</param>
    /// <param name="ipAddress">The IP address of the acting user, used for audit logging. Can be <see langword="null"/>.</param>
    /// <param name="userAgent">The user agent of the acting user, used for audit logging. Can be <see langword="null"/>.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/>.  Returns <see cref="ApiResult{T}.Ok"/>
    /// if the user is successfully created,  <see cref="ApiResult{T}.Fail"/> if the creation fails (e.g., due to
    /// missing fields or duplicate data),  or <see cref="ApiResult{T}.Forbidden"/> if the acting user lacks the
    /// required scope.</returns>
    public static ApiResult<MessageResponse> CreateUserScoped(
        ClaimsPrincipal actingUser,
        CreateUserRequest request,
        AppConfig config,
        string? ipAddress,
        string? userAgent)
    {
        if (!actingUser.HasScope(Constants.ProvisionUsers))
            return ApiResult<MessageResponse>.Forbidden("Permission Denied");

        if (string.IsNullOrWhiteSpace(request.Username) ||
            string.IsNullOrWhiteSpace(request.Email) ||
            string.IsNullOrWhiteSpace(request.Password))
        {
            return ApiResult<MessageResponse>.Fail("Username, email, and password are required");
        }

        var userId = Guid.NewGuid().ToString();
        var hash = AuthService.HashPassword(request.Password, config);

        var success = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                INSERT INTO users (id, username, password_hash, email, created_at)
                VALUES ($id, $username, $hash, $email, datetime('now'));
            """;
            cmd.Parameters.AddWithValue("$id", userId);
            cmd.Parameters.AddWithValue("$username", request.Username);
            cmd.Parameters.AddWithValue("$hash", hash);
            cmd.Parameters.AddWithValue("$email", request.Email);

            try
            {
                return cmd.ExecuteNonQuery() == 1;
            }
            catch (SqliteException)
            {
                return false;
            }
        });

        if (!success)
            return ApiResult<MessageResponse>.Fail("User creation failed (likely duplicate)");

        AuditLogger.AuditLog(
            userId: actingUser.GetUserId(),
            action: "user_created",
            target: userId,
            ipAddress: ipAddress,
            userAgent: userAgent
        );

        return ApiResult<MessageResponse>.Ok(new($"User '{request.Username}' created."));
    }

    /// <summary>
    /// Retrieves all user objects from the database, ordered by username in ascending order.
    /// </summary>
    /// <remarks>The method queries the database to fetch all user records and maps them to <see
    /// cref="UserResponse"/> objects. The returned list will be empty if no users are found in the database.</remarks>
    /// <returns>A list of <see cref="UserResponse"/> objects, where each object represents a user with their associated details
    /// such as ID, username, email, creation date, and active status.</returns>
    public static ApiResult<List<UserResponse>> GetAllUsers()
    {
        var users = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
            SELECT id, username, email, created_at, is_active
            FROM users
            ORDER BY username ASC;
        """;

            using var reader = cmd.ExecuteReader();
            var list = new List<UserResponse>();

            while (reader.Read())
            {
                list.Add(new UserResponse
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

        return ApiResult<List<UserResponse>>.Ok(users);
    }

    /// <summary>
    /// Retrieves a list of all users in the system, ordered by username.
    /// </summary>
    /// <remarks>This method requires the caller to have the <c>ListUsers</c> scope. If the caller does not
    /// have the required scope, the method returns a "Forbidden" result. The method also logs the action for auditing
    /// purposes, including the user ID, IP address, and user agent if provided.</remarks>
    /// <param name="actingUser">The <see cref="ClaimsPrincipal"/> representing the user making the request.  The user must have the required
    /// scope to access this method.</param>
    /// <param name="ipAddress">The IP address of the client making the request. This value is used for auditing purposes and can be null.</param>
    /// <param name="userAgent">The user agent string of the client making the request. This value is used for auditing purposes and can be
    /// null.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a list of <see cref="UserResponse"/> objects representing the users. If
    /// the caller lacks the required scope, the result will indicate a "Forbidden" status.</returns>
    public static ApiResult<List<UserResponse>> ListUsersScoped(
    ClaimsPrincipal actingUser,
    string? ipAddress,
    string? userAgent)
    {
        if (!actingUser.HasScope(Constants.ListUsers))
            return ApiResult<List<UserResponse>>.Forbidden("Permission denied");

        var users = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT id, username, email, created_at, is_active
                FROM users
                ORDER BY username ASC;
            """;

            using var reader = cmd.ExecuteReader();
            var list = new List<UserResponse>();

            while (reader.Read())
            {
                list.Add(new UserResponse
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

        AuditLogger.AuditLog(
            userId: actingUser.GetUserId(),
            action: "user_list",
            ipAddress: ipAddress,
            userAgent: userAgent
        );

        return ApiResult<List<UserResponse>>.Ok(users);
    }

    /// <summary>
    /// Retrieves a user by their unique identifier.
    /// </summary>
    /// <remarks>The method queries the database for a user with the specified ID. If the user exists, their
    /// details are returned in a <see cref="UserResponse"/> object. If the user does not exist, a "Not Found" result is
    /// returned.</remarks>
    /// <param name="userId">The unique identifier of the user to retrieve. Cannot be null, empty, or whitespace.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing the user details if found.  Returns a failure result with an
    /// appropriate error message and status code if the user ID is invalid or the user is not found.</returns>
    public static ApiResult<UserResponse> GetUserById(string userId)
    {
        if (string.IsNullOrWhiteSpace(userId))
            return ApiResult<UserResponse>.Fail("User ID is required", 400);

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
                return ApiResult<UserResponse>.NotFound("User not found");

            return ApiResult<UserResponse>.Ok(new UserResponse
            {
                Id = reader.GetString(0),
                Username = reader.GetString(1),
                Email = reader.GetString(2),
                CreatedAt = reader.GetString(3),
                IsActive = reader.GetInt64(4) == 1
            });
        });
    }

    /// <summary>
    /// Retrieves a user by their unique identifier, scoped to the permissions of the acting user.
    /// </summary>
    /// <remarks>This method enforces scope-based access control. The acting user must have the
    /// <c>Constants.ReadUser</c> scope to retrieve user information. If the user is found, an audit log entry is
    /// created to record the access.</remarks>
    /// <param name="actingUser">The <see cref="ClaimsPrincipal"/> representing the user making the request.  Must have the appropriate scope to
    /// read user information.</param>
    /// <param name="targetUserId">The unique identifier of the user to retrieve. This value cannot be null or empty.</param>
    /// <param name="ipAddress">The IP address of the client making the request. This value is optional and may be null.</param>
    /// <param name="userAgent">The user agent string of the client making the request. This value is optional and may be null.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing the <see cref="UserResponse"/> object if the user is found and
    /// accessible. Returns a "Forbidden" result if the acting user lacks the required scope, or a "Not Found" result if
    /// the user does not exist.</returns>
    public static ApiResult<UserResponse> GetUserByIdScoped(
        ClaimsPrincipal actingUser,
        string targetUserId,
        string? ipAddress,
        string? userAgent)
    {
        if (!actingUser.HasScope(Constants.ReadUser))
            return ApiResult<UserResponse>.Forbidden("Permission denied");

        var user = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT id, username, email, created_at, is_active
                FROM users
                WHERE id = $id;
            """;
            cmd.Parameters.AddWithValue("$id", targetUserId);

            using var reader = cmd.ExecuteReader();
            if (!reader.Read())
                return null;

            return new UserResponse
            {
                Id = reader.GetString(0),
                Username = reader.GetString(1),
                Email = reader.GetString(2),
                CreatedAt = reader.GetString(3),
                IsActive = reader.GetInt64(4) == 1
            };
        });

        if (user is null)
            return ApiResult<UserResponse>.NotFound("User not found");

        AuditLogger.AuditLog(
            userId: actingUser.GetUserId(),
            action: "user_read",
            target: targetUserId,
            ipAddress: ipAddress,
            userAgent: userAgent
        );

        return ApiResult<UserResponse>.Ok(user);
    }

    /// <summary>
    /// Deactivates a user by marking them as inactive in the system.
    /// </summary>
    /// <remarks>This method performs a soft delete by setting the user's active status to inactive.  If the
    /// user is already inactive or does not exist, the operation will fail with an appropriate message. An audit log
    /// entry is created for the deactivation event, including optional IP address and user agent information if
    /// provided.</remarks>
    /// <param name="userId">The unique identifier of the user to deactivate. Cannot be null, empty, or whitespace.</param>
    /// <param name="ip">The IP address of the requester. Optional.</param>
    /// <param name="ua">The user agent string of the requester. Optional.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/> with the result of the operation.
    /// Returns a success result if the user was successfully deactivated, or a failure result if the user was not found
    /// or already inactive.</returns>
    public static ApiResult<MessageResponse> SoftDeleteUser(string userId, string? ip = null, string? ua = null)
    {
        if (string.IsNullOrWhiteSpace(userId))
            return ApiResult<MessageResponse>.Fail("User ID is required", 400);

        var affected = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "UPDATE users SET is_active = 0 WHERE id = $id AND is_active = 1;";
            cmd.Parameters.AddWithValue("$id", userId);
            return cmd.ExecuteNonQuery();
        });

        if (affected == 0)
            return ApiResult<MessageResponse>.Fail("User not found or already inactive", 400);

        AuditLogger.AuditLog(
            userId: null, // you may capture admin user from route if desired
            action: "user_deactivated",
            target: userId,
            ipAddress: ip,
            userAgent: ua
        );

        return ApiResult<MessageResponse>.Ok(
            new MessageResponse($"User '{userId}' deactivated.")
        );
    }

    /// <summary>
    /// Deactivates a user account, marking it as inactive in the system.
    /// </summary>
    /// <remarks>This method requires the acting user to have the "admin:deactivate_users" scope.  Audit logs
    /// are created for successful deactivation attempts, including the acting user's ID, IP address, and user
    /// agent.</remarks>
    /// <param name="actingUser">The user performing the action. Must have the required scope to deactivate users.</param>
    /// <param name="targetUserId">The unique identifier of the user to deactivate. Cannot be null or whitespace.</param>
    /// <param name="ipAddress">The IP address of the acting user, used for audit logging. Can be null.</param>
    /// <param name="userAgent">The user agent of the acting user, used for audit logging. Can be null.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/> that indicates the result of the
    /// operation. Returns <see cref="ApiResult{T}.Forbidden"/> if the acting user lacks the required scope. Returns
    /// <see cref="ApiResult{T}.Fail"/> if the <paramref name="targetUserId"/> is invalid. Returns <see
    /// cref="ApiResult{T}.NotFound"/> if the user does not exist or is already inactive. Returns <see
    /// cref="ApiResult{T}.Ok"/> if the user was successfully deactivated.</returns>
    public static ApiResult<MessageResponse> DeactivateUserScoped(
    ClaimsPrincipal actingUser,
        string targetUserId,
        string? ipAddress,
        string? userAgent)
    {
        if (!actingUser.HasScope(Constants.DeactivateUsers))
            return ApiResult<MessageResponse>.Forbidden("Permission Denied");

        if (string.IsNullOrWhiteSpace(targetUserId))
            return ApiResult<MessageResponse>.Fail("User ID is required");

        var affected = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                UPDATE users
                SET is_active = 0
                WHERE id = $id AND is_active = 1;
            """;
            cmd.Parameters.AddWithValue("$id", targetUserId);
            return cmd.ExecuteNonQuery();
        });

        if (affected == 0)
            return ApiResult<MessageResponse>.NotFound("User not found or already inactive");

        AuditLogger.AuditLog(
            userId: actingUser.GetUserId(),
            action: "user_deactivated",
            target: targetUserId,
            ipAddress: ipAddress,
            userAgent: userAgent
        );

        return ApiResult<MessageResponse>.Ok(new($"User '{targetUserId}' deactivated."));
    }

    /// <summary>
    /// Reactivates a user account that has been soft-deleted.
    /// </summary>
    /// <remarks>This method updates the user's status in the database to mark them as active. It only affects
    /// users  who are currently soft-deleted (i.e., marked as inactive). Ensure the provided <paramref name="userId"/> 
    /// corresponds to a valid user in the database.</remarks>
    /// <param name="userId">The unique identifier of the user to reactivate. Cannot be null or empty.</param>
    /// <returns>The number of rows affected by the operation. Returns 1 if the user was successfully reactivated,  or 0 if no
    /// matching soft-deleted user was found.</returns>
    public static ApiResult<MessageResponse> ReactivateSoftDeletedUser(
        string userId,
        string? ip = null,
        string? ua = null
    )
    {
        if (string.IsNullOrWhiteSpace(userId))
            return ApiResult<MessageResponse>.Fail("User ID is required", 400);

        var affected = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "UPDATE users SET is_active = 1 WHERE id = $id AND is_active = 0;";
            cmd.Parameters.AddWithValue("$id", userId);
            return cmd.ExecuteNonQuery();
        });

        if (affected == 0)
            return ApiResult<MessageResponse>.Fail("User not found or already active", 400);

        AuditLogger.AuditLog(
            userId: null, // capture admin user if desired
            action: "user_reactivated",
            target: userId,
            ipAddress: ip,
            userAgent: ua
        );

        return ApiResult<MessageResponse>.Ok(
            new MessageResponse($"User '{userId}' reactivated.")
        );
    }


    /// <summary>
    /// Resets the password for a specified user.
    /// </summary>
    /// <remarks>This method updates the user's password in the database and logs the operation for auditing
    /// purposes.  The user must be active for the password reset to succeed. If the user is not found or inactive,  the
    /// method returns a failure result with a 400 status code.</remarks>
    /// <param name="userId">The unique identifier of the user whose password is being reset. Cannot be null or whitespace.</param>
    /// <param name="newPassword">The new password to set for the user. Cannot be null or whitespace.</param>
    /// <param name="config">The application configuration used for password hashing and other settings. Cannot be null.</param>
    /// <param name="ip">The IP address of the client initiating the request. Optional.</param>
    /// <param name="ua">The user agent string of the client initiating the request. Optional.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/>.  If successful, the response indicates
    /// that the password was reset.  If the operation fails, the response contains an error message and a status code.</returns>
    public static ApiResult<MessageResponse> ResetUserPassword(
        string userId,
        string newPassword,
        AppConfig config,
        string? ip = null,
        string? ua = null
)
    {
        if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(newPassword))
            return ApiResult<MessageResponse>.Fail("User ID and new password are required", 400);

        var hash = AuthService.HashPassword(newPassword, config);

        var affected = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                UPDATE users
                SET password_hash = $hash, modified_at = datetime('now')
                WHERE id = $id AND is_active = 1;
            """;
            cmd.Parameters.AddWithValue("$id", userId);
            cmd.Parameters.AddWithValue("$hash", hash);
            return cmd.ExecuteNonQuery();
        });

        if (affected == 0)
            return ApiResult<MessageResponse>.Fail("User not found or inactive", 400);

        AuditLogger.AuditLog(
            userId: null, // or capture the admin performing it, if applicable
            action: "user_password_reset",
            target: userId,
            ipAddress: ip,
            userAgent: ua
        );

        return ApiResult<MessageResponse>.Ok(
            new MessageResponse($"Password for user '{userId}' has been reset")
        );
    }

    /// <summary>
    /// Resets the password for a specified user, provided the acting user has the required scope.
    /// </summary>
    /// <remarks>This method updates the password hash for the specified user in the database and logs the
    /// operation for auditing purposes. The target user must be active for the operation to succeed.</remarks>
    /// <param name="actingUser">The user performing the operation. Must have the <see cref="Constants.ResetPasswords"/> scope.</param>
    /// <param name="targetUserId">The unique identifier of the user whose password is being reset.</param>
    /// <param name="newPassword">The new password to set for the target user. Cannot be null, empty, or whitespace.</param>
    /// <param name="config">The application configuration used for password hashing and other settings.</param>
    /// <param name="ipAddress">The IP address of the acting user, used for audit logging. Can be null.</param>
    /// <param name="userAgent">The user agent of the acting user, used for audit logging. Can be null.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/> that indicates the result of the
    /// operation: <list type="bullet"> <item><description><see cref="ApiResult{T}.Ok"/> if the password was
    /// successfully reset.</description></item> <item><description><see cref="ApiResult{T}.Forbidden"/> if the acting
    /// user lacks the required scope.</description></item> <item><description><see cref="ApiResult{T}.Fail"/> if the
    /// <paramref name="newPassword"/> is invalid.</description></item> <item><description><see
    /// cref="ApiResult{T}.NotFound"/> if the target user does not exist or is inactive.</description></item> </list></returns>
    public static ApiResult<MessageResponse> ResetUserPasswordScoped(
        ClaimsPrincipal actingUser,
        string targetUserId,
        string newPassword,
        AppConfig config,
        string? ipAddress,
        string? userAgent)
    {
        if (!actingUser.HasScope(Constants.ResetPasswords))
            return ApiResult<MessageResponse>.Forbidden("Permission Denied");

        if (string.IsNullOrWhiteSpace(newPassword))
            return ApiResult<MessageResponse>.Fail("New password is required");

        var hash = AuthService.HashPassword(newPassword, config);

        var affected = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                UPDATE users
                SET password_hash = $hash, modified_at = datetime('now')
                WHERE id = $uid AND is_active = 1;
            """;
            cmd.Parameters.AddWithValue("$hash", hash);
            cmd.Parameters.AddWithValue("$uid", targetUserId);

            return cmd.ExecuteNonQuery();
        });

        if (affected == 0)
            return ApiResult<MessageResponse>.NotFound("User not found or already inactive");

        AuditLogger.AuditLog(
            userId: actingUser.GetUserId(),
            action: "user_password_reset",
            target: targetUserId,
            ipAddress: ipAddress,
            userAgent: userAgent
        );

        return ApiResult<MessageResponse>.Ok(new($"Password for user '{targetUserId}' has been reset."));
    }

    /// <summary>
    /// Writes a session record to the database using the provided token information.
    /// </summary>
    /// <remarks>This method inserts a new session record into the database. The session is marked as
    /// active (not revoked) upon creation. Ensure that the database connection is properly configured in the
    /// application settings before calling this method.</remarks>
    /// <param name="token">The <see cref="TokenInfo"/> object containing details about the session, including the token ID, user ID,
    /// token value, issue time, and expiration time. All properties must be populated.</param>
    /// <param name="config">The <see cref="AppConfig"/> object containing application-specific configuration settings. This parameter is
    /// required to establish a database connection.</param>
    public static void WriteSessionToDb(TokenInfo token, AppConfig config, string clientIdent)
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
    /// Retrieves all session records from the database, ordered by their issuance date in descending order.
    /// </summary>
    /// <remarks>This method queries the database for all session records and returns them as a list of <see
    /// cref="SessionResponse"/> objects. Each session includes details such as its ID, associated user ID, issuance and
    /// expiration timestamps, revocation status, and token usage type. If the operation fails, an error result is
    /// returned with a status code of 500.</remarks>
    /// <returns>An <see cref="ApiResult{T}"/> containing a list of <see cref="SessionResponse"/> objects if the operation
    /// succeeds. If the operation fails, the result contains an error message and a status code of 500.</returns>
    public static ApiResult<List<SessionResponse>> GetAllSessions()
    {
        try
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

            return ApiResult<List<SessionResponse>>.Ok(sessions);
        }
        catch
        {
            return ApiResult<List<SessionResponse>>.Fail("Failed to load sessions", 500);
        }
    }


    /// <summary>
    /// Retrieves a session by its unique identifier (JTI).
    /// </summary>
    /// <remarks>This method queries the database for a session with the specified JTI. If the session is
    /// found, it returns a successful result containing the session details. If the session is not found, it returns a
    /// "Not Found" result. If the input JTI is invalid, it returns a failure result with a 400 status code.</remarks>
    /// <param name="jti">The unique identifier of the session to retrieve. Cannot be null, empty, or whitespace.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing the session details if found, or an error result if the session is not
    /// found or the input is invalid.</returns>
    public static ApiResult<SessionResponse> GetSessionById(string jti)
    {
        if (string.IsNullOrWhiteSpace(jti))
            return ApiResult<SessionResponse>.Fail("Session ID is required", 400);

        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT id, user_id, issued_at, expires_at, is_revoked, token_use
                FROM sessions
                WHERE id = $jti;
            """;
            cmd.Parameters.AddWithValue("$jti", jti);

            using var reader = cmd.ExecuteReader();
            if (!reader.Read())
                return ApiResult<SessionResponse>.NotFound("Session not found");

            return ApiResult<SessionResponse>.Ok(new SessionResponse
            {
                Id = reader.GetString(0),
                UserId = reader.GetString(1),
                IssuedAt = DateTime.Parse(reader.GetString(2)),
                ExpiresAt = DateTime.Parse(reader.GetString(3)),
                IsRevoked = reader.GetInt64(4) == 1,
                TokenUse = reader.GetString(5)
            });
        });
    }

    /// <summary>
    /// Retrieves a list of session details for a specified user.
    /// </summary>
    /// <remarks>The sessions are retrieved from the database and ordered by their issuance date in descending
    /// order. Each session includes details such as its ID, issuance and expiration times, revocation status, and token
    /// usage.</remarks>
    /// <param name="userId">The unique identifier of the user whose sessions are to be retrieved. Cannot be null, empty, or whitespace.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a list of <see cref="SessionResponse"/> objects representing the user's
    /// sessions. If the operation fails, the result will include an error message and an appropriate HTTP status code.</returns>
    public static ApiResult<List<SessionResponse>> GetSessionsByUserId(string userId)
    {
        if (string.IsNullOrWhiteSpace(userId))
            return ApiResult<List<SessionResponse>>.Fail("User ID is required", 400);

        try
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

            return ApiResult<List<SessionResponse>>.Ok(sessions);
        }
        catch
        {
            return ApiResult<List<SessionResponse>>.Fail("Failed to retrieve sessions", 500);
        }
    }

    /// <summary>
    /// Retrieves a list of active sessions for the current user.
    /// </summary>
    /// <remarks>Active sessions are defined as sessions that are not revoked and have not expired.  The
    /// sessions are returned in descending order of their issuance time.</remarks>
    /// <param name="userId">The unique identifier of the user whose active sessions are to be retrieved.  This parameter cannot be null,
    /// empty, or consist only of whitespace.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a list of <see cref="SessionResponse"/> objects representing the user's
    /// active sessions.  If the <paramref name="userId"/> is invalid, the result will indicate failure with an
    /// appropriate error message and status code.</returns>
    public static ApiResult<List<SessionResponse>> GetSessionsForSelf(string userId)
    {
        if (string.IsNullOrWhiteSpace(userId))
            return ApiResult<List<SessionResponse>>.Fail("Invalid user", 401);

        var sessions = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT id, user_id, issued_at, expires_at, is_revoked, token_use
                FROM sessions
                WHERE user_id = $uid
                  AND is_revoked = 0
                  AND expires_at > datetime('now')
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

        return ApiResult<List<SessionResponse>>.Ok(sessions);
    }

    /// <summary>
    /// Retrieves a list of refresh tokens associated with the specified user.
    /// </summary>
    /// <remarks>The refresh tokens are returned in descending order of their issuance date. Each token
    /// includes details such as its ID, associated session,  issuance and expiration timestamps, and revocation
    /// status.</remarks>
    /// <param name="userId">The unique identifier of the user whose refresh tokens are to be retrieved. Cannot be null, empty, or
    /// whitespace.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a list of <see cref="RefreshTokenResponse"/> objects representing the
    /// user's refresh tokens. If the <paramref name="userId"/> is null, empty, or whitespace, the result is an
    /// unauthorized response.</returns>
    public static ApiResult<List<RefreshTokenResponse>> GetRefreshTokensForSelf(string? userId)
    {
        if (string.IsNullOrWhiteSpace(userId))
            return ApiResult<List<RefreshTokenResponse>>.Forbidden();

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

        return ApiResult<List<RefreshTokenResponse>>.Ok(tokens);
    }

    /// <summary>
    /// Revokes a session identified by its unique token identifier (JTI).
    /// </summary>
    /// <remarks>This method checks the session's current state before attempting to revoke it: <list
    /// type="bullet"> <item>If the session is already revoked, the response indicates that the session was previously
    /// revoked.</item> <item>If the session has expired, the response indicates that the session has already
    /// expired.</item> <item>If the session is active, it is revoked, and an audit log entry is created for the
    /// revocation.</item> </list> The method returns a 400 status code if the <paramref name="jti"/> is null, empty, or
    /// whitespace, and a 404 status code if the session is not found.</remarks>
    /// <param name="jti">The unique token identifier (JTI) of the session to revoke. This parameter cannot be null, empty, or whitespace.</param>
    /// <param name="ip">The IP address of the client initiating the revocation. This parameter is optional and can be null.</param>
    /// <param name="ua">The user agent string of the client initiating the revocation. This parameter is optional and can be null.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="RevokeResponse"/> object that describes the result of the
    /// revocation. The response includes the JTI, the revocation status, and a message providing additional details.</returns>
    public static ApiResult<RevokeResponse> RevokeSessionById(string jti, string? ip = null, string? ua = null)
    {
        if (string.IsNullOrWhiteSpace(jti))
            return ApiResult<RevokeResponse>.Fail("Missing JTI", 400);

        return Db.WithConnection(conn =>
        {
            using var getCmd = conn.CreateCommand();
            getCmd.CommandText = """
                SELECT user_id, issued_at, expires_at, is_revoked, token_use
                FROM sessions
                WHERE id = $jti;
            """;
            getCmd.Parameters.AddWithValue("$jti", jti);

            using var reader = getCmd.ExecuteReader();
            if (!reader.Read())
                return ApiResult<RevokeResponse>.NotFound("Session not found");

            var userId = reader.GetString(0);
            var expiresAt = DateTime.Parse(reader.GetString(2));
            var isRevoked = reader.GetInt64(3) == 1;

            if (isRevoked)
            {
                return ApiResult<RevokeResponse>.Ok(new RevokeResponse
                {
                    Jti = jti,
                    Status = "already_revoked",
                    Message = $"Session {jti} has already been revoked."
                });
            }

            if (expiresAt < DateTime.UtcNow)
            {
                return ApiResult<RevokeResponse>.Ok(new RevokeResponse
                {
                    Jti = jti,
                    Status = "expired",
                    Message = $"Session {jti} has already expired."
                });
            }

            using var updateCmd = conn.CreateCommand();
            updateCmd.CommandText = "UPDATE sessions SET is_revoked = 1 WHERE id = $jti;";
            updateCmd.Parameters.AddWithValue("$jti", jti);
            updateCmd.ExecuteNonQuery();

            AuditLogger.AuditLog(
                userId: userId,
                action: "session_revoked",
                target: jti,
                ipAddress: ip,
                userAgent: ua
            );

            return ApiResult<RevokeResponse>.Ok(new RevokeResponse
            {
                Jti = jti,
                Status = "revoked",
                Message = $"Session {jti} has been revoked successfully."
            });
        });
    }


    /// <summary>
    /// Purges user sessions from the database based on specified conditions.
    /// </summary>
    /// <remarks>This method allows selective purging of user sessions based on their expiration status,
    /// revocation status, or both. If neither <paramref name="purgeExpired"/> nor <paramref name="purgeRevoked"/> is
    /// <see langword="true"/>, no sessions will be purged, and the method will return a message indicating that no
    /// action was taken. Audit logging is performed for all purge operations, including details about the number of
    /// sessions purged and the conditions used.</remarks>
    /// <param name="olderThan">The time span used to determine the cutoff for expired sessions. Sessions older than this value will be
    /// considered for purging if <paramref name="purgeExpired"/> is <see langword="true"/>.</param>
    /// <param name="purgeExpired">A value indicating whether to purge sessions that have expired.</param>
    /// <param name="purgeRevoked">A value indicating whether to purge sessions that have been explicitly revoked.</param>
    /// <param name="ip">The IP address of the requester, used for audit logging. This parameter is optional and can be <see
    /// langword="null"/>.</param>
    /// <param name="ua">The user agent of the requester, used for audit logging. This parameter is optional and can be <see
    /// langword="null"/>.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/> that describes the result of the
    /// operation. If no sessions match the specified conditions, the message will indicate that nothing was purged.
    /// Otherwise, the message will specify the number of sessions that were purged.</returns>
    public static ApiResult<MessageResponse> PurgeSessions(
    TimeSpan olderThan,
    bool purgeExpired,
    bool purgeRevoked,
    string? userId = null,
    string? ip = null,
    string? ua = null)
    {
        var conditions = new List<string>();
        if (purgeExpired)
            conditions.Add("expires_at < datetime('now', $cutoff)");
        if (purgeRevoked)
            conditions.Add("is_revoked = 1");

        if (conditions.Count == 0)
            return ApiResult<MessageResponse>.Ok(new("Nothing to purge."));

        var whereClause = string.Join(" OR ", conditions);

        var purged = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = $"DELETE FROM sessions WHERE {whereClause};";

            if (purgeExpired)
                cmd.Parameters.AddWithValue("$cutoff", $"-{(int)olderThan.TotalSeconds} seconds");

            return cmd.ExecuteNonQuery();
        });

        AuditLogger.AuditLog(
            userId: userId,
            action: "sessions_purged",
            target: $"purged={purged};expired={purgeExpired};revoked={purgeRevoked}",
            ipAddress: ip,
            userAgent: ua
        );

        return ApiResult<MessageResponse>.Ok(new($"Purged {purged} session(s)."));
    }


    /// <summary>
    /// Generates a new refresh token, stores its hashed value in the database, and returns the raw token.
    /// </summary>
    /// <remarks>The raw token is returned to the caller, while only its hashed value is stored in the
    /// database for security purposes. The token is generated using a cryptographically secure random number
    /// generator and hashed using the Argon2id algorithm. The expiration time of the token is determined by the
    /// <see cref="AppConfig.RefreshTokenExpiration"/> setting.</remarks>
    /// <param name="config">The application configuration containing settings for token expiration and hashing parameters.</param>
    /// <param name="userId">The unique identifier of the user for whom the refresh token is being generated.</param>
    /// <param name="sessionId">The unique identifier of the session associated with the refresh token.</param>
    /// <returns>A base64-encoded string representing the raw refresh token. This token should be securely sent to the client
    /// and stored for subsequent authentication requests.</returns>
    public static string GenerateAndStoreRefreshToken(
        AppConfig config,
        string userId,
        string sessionId,
        string clientIdent)
    {
        var raw = Utils.GenerateBase64EncodedRandomBytes(32);
        var now = DateTime.UtcNow;
        var expires = now.AddSeconds(config.RefreshTokenExpiration);

        byte[] salt = new byte[config.Argon2SaltLength];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(salt);

        var hash = Argon2.Argon2HashEncodedToString(
            Argon2Algorithm.Argon2id,
            (uint)config.Argon2Time,
            (uint)config.Argon2Memory,
            (uint)config.Argon2Parallelism,
            Encoding.UTF8.GetBytes(raw),
            salt,
            config.Argon2HashLength
        );

        var id = Guid.NewGuid().ToString();

        var sha256 = Utils.Sha256Base64(raw);

        // We do not store the raw token, only the argon2id hash and its SHA-256 for quick lookup
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
            cmd.Parameters.AddWithValue("$sha256", sha256);
            cmd.Parameters.AddWithValue("$issuedAt", now.ToString("o"));
            cmd.Parameters.AddWithValue("$expiresAt", expires.ToString("o"));
            cmd.ExecuteNonQuery();
        });

        return raw; // return the un-hashed token to send to client
    }

    /// <summary>
    /// Retrieves all refresh tokens from the database, ordered by their issuance date in descending order.
    /// </summary>
    /// <remarks>This method queries the database for all refresh tokens and returns them as a list of <see
    /// cref="RefreshTokenResponse"/> objects. Each token includes details such as its ID, associated user ID, session
    /// ID, issuance and expiration timestamps, and revocation status.</remarks>
    /// <returns>An <see cref="ApiResult{T}"/> containing a list of <see cref="RefreshTokenResponse"/> objects if the operation
    /// succeeds. If the operation fails, the result contains an error message and a status code of 500.</returns>
    public static ApiResult<List<RefreshTokenResponse>> GetAllRefreshTokens()
    {
        try
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

            return ApiResult<List<RefreshTokenResponse>>.Ok(tokens);
        }
        catch
        {
            return ApiResult<List<RefreshTokenResponse>>.Fail("Failed to retrieve refresh tokens", 500);
        }
    }


    /// <summary>
    /// Retrieves a refresh token by its unique identifier.
    /// </summary>
    /// <remarks>This method queries the database for a refresh token with the specified <paramref
    /// name="tokenId"/>. If the token is found, its details are returned in a <see cref="RefreshTokenResponse"/>
    /// object. If the token is not found, the result will indicate a "not found" status.</remarks>
    /// <param name="tokenId">The unique identifier of the refresh token to retrieve. Cannot be null, empty, or whitespace.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing the refresh token details if found, or an error result if the token is
    /// not found or the <paramref name="tokenId"/> is invalid.</returns>
    public static ApiResult<RefreshTokenResponse> GetRefreshTokenById(string tokenId)
    {
        if (string.IsNullOrWhiteSpace(tokenId))
            return ApiResult<RefreshTokenResponse>.Fail("Token ID is required", 400);

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
                return ApiResult<RefreshTokenResponse>.NotFound("Refresh token not found");

            return ApiResult<RefreshTokenResponse>.Ok(new RefreshTokenResponse
            {
                Id = reader.GetString(0),
                UserId = reader.GetString(1),
                SessionId = reader.GetString(2),
                IssuedAt = DateTime.Parse(reader.GetString(3)),
                ExpiresAt = DateTime.Parse(reader.GetString(4)),
                IsRevoked = reader.GetInt64(5) == 1
            });
        });
    }


    /// <summary>
    /// Retrieves a list of refresh tokens associated with the specified user ID.
    /// </summary>
    /// <remarks>The refresh tokens are retrieved from the database and ordered by their issuance date in
    /// descending order. If no tokens are found for the specified user, the returned list will be empty.</remarks>
    /// <param name="userId">The unique identifier of the user whose refresh tokens are to be retrieved. Cannot be null, empty, or
    /// whitespace.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a list of <see cref="RefreshTokenResponse"/> objects representing the
    /// user's refresh tokens. If the operation fails, the result contains an error message and an appropriate HTTP
    /// status code.</returns>
    public static ApiResult<List<RefreshTokenResponse>> GetRefreshTokensByUserId(string userId)
    {
        if (string.IsNullOrWhiteSpace(userId))
            return ApiResult<List<RefreshTokenResponse>>.Fail("User ID is required", 400);

        try
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

            return ApiResult<List<RefreshTokenResponse>>.Ok(tokens);
        }
        catch
        {
            return ApiResult<List<RefreshTokenResponse>>.Fail("Failed to retrieve refresh tokens", 500);
        }
    }


    /// <summary>
    /// Deletes refresh tokens from the database based on the specified purge criteria.
    /// </summary>
    /// <remarks>This method evaluates the provided criteria in <paramref name="req"/> to determine which
    /// refresh tokens to delete. If no criteria are specified, no tokens are purged, and a success message is returned
    /// indicating that nothing was purged. Audit logging is performed to record the operation, including the number of
    /// tokens purged and the criteria used.</remarks>
    /// <param name="req">The request containing the criteria for purging refresh tokens, such as whether to purge expired or revoked
    /// tokens.</param>
    /// <param name="userId">The optional identifier of the user performing the operation, used for audit logging.</param>
    /// <param name="ip">The optional IP address of the user performing the operation, used for audit logging.</param>
    /// <param name="ua">The optional user agent string of the user performing the operation, used for audit logging.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/> that describes the result of the
    /// operation. The message indicates the number of tokens purged or specifies that no tokens were purged if no
    /// criteria were met.</returns>
    public static ApiResult<MessageResponse> PurgeRefreshTokens(
        PurgeTokensRequest req,
        string? userId = null,
        string? ip = null,
        string? ua = null)
    {
        var conditions = new List<string>();
        if (req.PurgeExpired)
            conditions.Add("expires_at < datetime('now', $cutoff)");
        if (req.PurgeRevoked)
            conditions.Add("is_revoked = 1");

        if (conditions.Count == 0)
            return ApiResult<MessageResponse>.Ok(new("Nothing to purge."));

        string whereClause = string.Join(" OR ", conditions);

        int purged = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = $"DELETE FROM refresh_tokens WHERE {whereClause};";

            if (req.PurgeExpired)
                cmd.Parameters.AddWithValue("$cutoff", $"-{req.OlderThanSeconds} seconds");

            return cmd.ExecuteNonQuery();
        });

        AuditLogger.AuditLog(
            userId: userId,
            action: "refresh_tokens_purged",
            target: $"purged={purged};expired={req.PurgeExpired};revoked={req.PurgeRevoked}",
            ipAddress: ip,
            userAgent: ua
        );

        return ApiResult<MessageResponse>.Ok(new($"Purged {purged} refresh token(s)."));
    }

}
