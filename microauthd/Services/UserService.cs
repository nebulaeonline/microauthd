using madTypes.Api.Common;
using madTypes.Api.Requests;
using madTypes.Api.Responses;
using madTypes.Common;
using microauthd.Common;
using microauthd.Config;
using microauthd.Data;
using Microsoft.Data.Sqlite;
using nebulae.dotArgon2;
using OtpNet;
using QRCoder;
using Serilog;
using System.CommandLine.Parsing;
using System.Diagnostics.Eventing.Reader;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using static microauthd.Tokens.TokenIssuer;
using static nebulae.dotArgon2.Argon2;

namespace microauthd.Services;

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
    public static ApiResult<UserObject> CreateUser(
        string username,
        string email,
        string password,
        AppConfig config
)
    {
        if (string.IsNullOrWhiteSpace(username) ||
            string.IsNullOrWhiteSpace(email) ||
            string.IsNullOrWhiteSpace(password))
        {
            return ApiResult<UserObject>.Fail("Username, email, and password are required", 400);
        }

        var userId = Guid.NewGuid().ToString();
        var passwordHash = AuthService.HashPassword(password, config);

        try
        {
            var user = UserStore.CreateUser(
                userId: userId,
                username: username,
                email: email,
                passwordHash: passwordHash
            );

            if (config.EnableAuditLogging)
                Utils.Audit.Logg(
                    action: "user_created",
                    target: username,
                    secondary: userId
                );

            if (user is null)
            {
                return ApiResult<UserObject>.Fail("User creation failed, user not found after insert", 400);
            }

            return ApiResult<UserObject>.Ok(user);
        }
        catch (Exception ex)
        {
            Log.Error($"Failed to create user {userId} / {username} / {email}: {ex.Message}");
            return ApiResult<UserObject>.Fail("User creation failed (maybe duplicate username?)", 400);
        }
    }

    /// <summary>
    /// Creates a new user scoped to the provided request and acting user's permissions.
    /// </summary>
    /// <remarks>This method validates the acting user's permissions and the provided user details before
    /// attempting to create a new user.  If successful, the user is created, and an audit log entry is recorded.  If
    /// the operation fails, an appropriate error message is returned.</remarks>
    /// <param name="actingUser">The <see cref="ClaimsPrincipal"/> representing the user performing the operation. Must have the required scope
    /// to provision users.</param>
    /// <param name="request">The <see cref="CreateUserRequest"/> containing the details of the user to be created, including username, email,
    /// and password.</param>
    /// <param name="config">The application configuration used for password hashing and auditing.</param>
    /// <param name="ipAddress">The IP address of the client making the request. Used for auditing purposes. Can be <see langword="null"/>.</param>
    /// <param name="userAgent">The user agent string of the client making the request. Used for auditing purposes. Can be <see
    /// langword="null"/>.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing the created <see cref="UserObject"/> if successful.  Returns a failure
    /// result if the acting user lacks the required permissions, if required fields are missing,  or if user creation
    /// fails due to a duplicate or other error.</returns>
    public static ApiResult<UserObject> CreateUserScoped(
        ClaimsPrincipal actingUser,
        CreateUserRequest request,
        AppConfig config)
    {
        if (!actingUser.HasScope(Constants.Scope_ProvisionUsers))
            return ApiResult<UserObject>.Forbidden("Permission Denied");

        if (string.IsNullOrWhiteSpace(request.Username) ||
            string.IsNullOrWhiteSpace(request.Email) ||
            string.IsNullOrWhiteSpace(request.Password))
        {
            return ApiResult<UserObject>.Fail("Username, email, and password are required");
        }

        var userId = Guid.NewGuid().ToString();
        var hash = AuthService.HashPassword(request.Password, config);

        try
        {
            var user = UserStore.CreateUser(
                userId: userId,
                username: request.Username,
                email: request.Email,
                passwordHash: hash
            );

            if (user is null)
                return ApiResult<UserObject>.Fail("User creation failed (likely duplicate)");

            if (config.EnableAuditLogging)
                Utils.Audit.Logg(
                    action: "user_created",
                    target: userId,
                    secondary: request.Username
                );

            return ApiResult<UserObject>.Ok(user);
        }
        catch (Exception ex)
        {
            Log.Error($"Failed to create user {userId} / {request.Username} / {request.Email}: {ex.Message}");
            return ApiResult<UserObject>.Fail("User creation failed");
        }
    }

    /// <summary>
    /// Updates the details of an existing user in the database.
    /// </summary>
    /// <remarks>The method performs the following validations and operations: <list type="bullet"> <item>
    /// <description>Ensures that the <paramref name="updated"/> object contains a non-empty username and
    /// email.</description> </item> <item> <description>Checks for conflicts with existing users based on username or
    /// email.</description> </item> <item> <description>Updates the user's details in the database if no conflicts are
    /// found.</description> </item> <item> <description>Returns the updated user object if the operation is successful,
    /// or an error message if it fails.</description> </item> </list></remarks>
    /// <param name="id">The unique identifier of the user to update.</param>
    /// <param name="updated">An object containing the updated user details, including username, email, and active status.</param>
    /// <param name="config">The application configuration used for database access and other settings.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing the updated <see cref="UserObject"/> if the operation succeeds;
    /// otherwise, an error message indicating the reason for failure.</returns>
    public static ApiResult<UserObject> UpdateUser(
        string id,
        UserObject updated,
        AppConfig config
    )
    {
        if (string.IsNullOrWhiteSpace(updated.Username) || string.IsNullOrWhiteSpace(updated.Email))
            return ApiResult<UserObject>.Fail("Username and email are required.");

        try
        {
            // Check for duplicate username/email
            var conflict = UserStore.CheckForUsernameOrEmailConflict(updated.Id, updated.Username, updated.Email);

            if (conflict)
                return ApiResult<UserObject>.Fail("Username or email already in use by another user.");

            // Do the update
            var success = UserStore.UpdateUser(updated);

            if (!success)
                return ApiResult<UserObject>.Fail("Update failed or user not found.");

            // Re-read and return updated row
            var user = UserStore.GetUserById(updated.Id);

            return user is not null
                ? ApiResult<UserObject>.Ok(user)
                : ApiResult<UserObject>.Fail("User updated but could not be retrieved.");
        }
        catch (Exception ex)
        {
            Log.Error($"Failed to update user {id}: {ex.Message}");
            return ApiResult<UserObject>.Fail("User update failed due to an error.");
        }
    }

    /// <summary>
    /// Marks the email address of a user as verified.
    /// </summary>
    /// <param name="id">The unique identifier of the user whose email address is to be marked as verified. Cannot be null or empty.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/>.  Returns a success result if the email
    /// verification status was updated successfully;  otherwise, returns a failure result with an appropriate error
    /// message.</returns>
    public static ApiResult<MessageResponse> MarkEmailVerified(string id)
    {
        var updated = UserStore.GetUserById(id);
        
        if (updated is null)
            return ApiResult<MessageResponse>.Fail("User not found.", 404);

        updated.EmailVerified = true;

        var ok = UserStore.UpdateUser(updated);

        return ok
            ? ApiResult<MessageResponse>.Ok(new MessageResponse(true, "Email marked as verified.")) 
            : ApiResult<MessageResponse>.Fail("Could not update user's email verification status.");
    }

    /// <summary>
    /// Retrieves all user objects from the database, ordered by username in ascending order.
    /// </summary>
    /// <remarks>The method queries the database to fetch all user records and maps them to <see
    /// cref="UserObject"/> objects. The returned list will be empty if no users are found in the database.</remarks>
    /// <returns>A list of <see cref="UserObject"/> objects, where each object represents a user with their associated details
    /// such as ID, username, email, creation date, and active status.</returns>
    public static ApiResult<List<UserObject>> ListUsers()
    {
        try
        {
            var users = UserStore.ListUsers();
            return ApiResult<List<UserObject>>.Ok(users);
        }
        catch (Exception ex)
        {
            Log.Error($"Failed to retrieve users: {ex.Message}");
            return ApiResult<List<UserObject>>.Fail("Failed to retrieve users from the database.");
        }
    }

    /// <summary>
    /// Retrieves the user ID associated with the specified username.
    /// </summary>
    /// <remarks>This method returns a successful result if the user ID is found, or an error result with an
    /// appropriate status code and message if the username is invalid or the user does not exist.</remarks>
    /// <param name="username">The username of the user whose ID is to be retrieved. Cannot be null, empty, or consist solely of whitespace.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing the user ID if the username exists, or an error result if the username
    /// is invalid or the user is not found.</returns>
    public static ApiResult<string> GetUserIdByUsername(string username)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(username))
                return ApiResult<string>.Fail("Username is required", 400);

            var id = UserStore.GetUserIdByUsername(username);

            return id == null
                ? ApiResult<string>.Fail("User not found", 404)
                : ApiResult<string>.Ok(id);
        }
        catch (Exception ex)
        {
            Log.Error($"Failed to retrieve user ID for username {username}: {ex.Message}");
            return ApiResult<string>.Fail("Failed to retrieve user ID from the database.", 500);
        }
    }

    /// <summary>
    /// Deletes a user with the specified identifier from the database.
    /// </summary>
    /// <remarks>This method executes a database operation to delete a user by their unique identifier. 
    /// Ensure that the provided <paramref name="idToDelete"/> corresponds to an existing user in the database.</remarks>
    /// <param name="idToDelete">The unique identifier of the user to delete. Cannot be null or empty.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/> object.  If the user is successfully
    /// deleted, the result is <see cref="ApiResult{T}.Ok"/> with a success message.  If the user is not found, the
    /// result is <see cref="ApiResult{T}.NotFound"/> with an error message.</returns>
    public static ApiResult<MessageResponse> DeleteUser(
        string idToDelete,
        AppConfig config)
    {
        try
        {
            // Delete the user
            var deleted = UserStore.DeleteUser(idToDelete);

            // Revoke sessions
            UserStore.RevokeUserSessions(idToDelete);

            // Revoke refresh tokens
            UserStore.RevokeUserRefreshTokens(idToDelete);

            if (config.EnableAuditLogging) 
                Utils.Audit.Logg("delete_user", idToDelete);

            return deleted
                ? ApiResult<MessageResponse>.Ok(new(true, $"Deleted user {idToDelete}"))
                : ApiResult<MessageResponse>.NotFound($"User {idToDelete} not found.");
        }
        catch (Exception ex)
        {
            Log.Error($"Failed to delete user {idToDelete}: {ex.Message}");
            return ApiResult<MessageResponse>.Fail("Failed to delete user from the database.", 500);
        }
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
    /// <returns>An <see cref="ApiResult{T}"/> containing a list of <see cref="UserObject"/> objects representing the users. If
    /// the caller lacks the required scope, the result will indicate a "Forbidden" status.</returns>
    public static ApiResult<List<UserObject>> ListUsersScoped(
    ClaimsPrincipal actingUser,
    AppConfig config,
    string? ipAddress,
    string? userAgent)
    {
        if (!actingUser.HasScope(Constants.Scope_ListUsers))
            return ApiResult<List<UserObject>>.Forbidden("Permission denied");

        try
        {
            var users = UserStore.ListUsers();

            if (config.EnableAuditLogging)
                Utils.Audit.Logg(
                    action: "user_list",
                    null
                );

            return ApiResult<List<UserObject>>.Ok(users);
        }
        catch (Exception ex)
        {
            Log.Error($"Failed to list users: {ex.Message}");
            return ApiResult<List<UserObject>>.Fail("Failed to retrieve users from the database.", 500);
        }
    }

    /// <summary>
    /// Retrieves a user by their unique identifier.
    /// </summary>
    /// <remarks>The method queries the database for a user with the specified ID. If the user exists, their
    /// details are returned in a <see cref="UserObject"/> object. If the user does not exist, a "Not Found" result is
    /// returned.</remarks>
    /// <param name="userId">The unique identifier of the user to retrieve. Cannot be null, empty, or whitespace.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing the user details if found.  Returns a failure result with an
    /// appropriate error message and status code if the user ID is invalid or the user is not found.</returns>
    public static ApiResult<UserObject> GetUserById(string userId)
    {
        if (string.IsNullOrWhiteSpace(userId))
            return ApiResult<UserObject>.Fail("User ID is required", 400);

        try
        {
            var user = UserStore.GetUserById(userId);

            if (user is null)
                return ApiResult<UserObject>.NotFound("User not found");

            return ApiResult<UserObject>.Ok(user);
        }
        catch (Exception ex)
        {
            Log.Error($"Failed to retrieve user {userId}: {ex.Message}");
            return ApiResult<UserObject>.Fail("Failed to retrieve user from the database.", 500);
        }
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
    /// <returns>An <see cref="ApiResult{T}"/> containing the <see cref="UserObject"/> object if the user is found and
    /// accessible. Returns a "Forbidden" result if the acting user lacks the required scope, or a "Not Found" result if
    /// the user does not exist.</returns>
    public static ApiResult<UserObject> GetUserByIdScoped(
        ClaimsPrincipal actingUser,
        string targetUserId,
        AppConfig config,
        string? ipAddress,
        string? userAgent)
    {
        if (!actingUser.HasScope(Constants.Scope_ReadUser))
            return ApiResult<UserObject>.Forbidden("Permission denied");

        try
        {
            var user = UserStore.GetUserById(targetUserId);

            if (user is null)
                return ApiResult<UserObject>.NotFound("User not found");

            if (config.EnableAuditLogging)
                Utils.Audit.Logg(
                    action: "user_read",
                    target: targetUserId
                );

            return ApiResult<UserObject>.Ok(user);
        }
        catch (Exception ex)
        {
            Log.Error($"Failed to retrieve user {targetUserId}: {ex.Message}");
            return ApiResult<UserObject>.Fail("Failed to retrieve user from the database.", 500);
        }
    }

    /// <summary>
    /// Deactivates a user account and revokes all associated sessions and refresh tokens.
    /// </summary>
    /// <remarks>This method performs the following actions: <list type="bullet">
    /// <item><description>Deactivates the user account in the database.</description></item> <item><description>Revokes
    /// all active sessions and refresh tokens associated with the user.</description></item> <item><description>Logs an
    /// audit entry for the deactivation action, including optional IP address and user agent
    /// information.</description></item> </list> If the user is not found or is already inactive, the method returns a
    /// failure response with a 400 status code. If an unexpected error occurs, the method logs the error and returns a
    /// failure response with a 500 status code.</remarks>
    /// <param name="userId">The unique identifier of the user to deactivate. Cannot be null, empty, or whitespace.</param>
    /// <param name="config">The application configuration used for logging and auditing purposes. Cannot be null.</param>
    /// <param name="ip">The IP address of the requester, used for auditing. Optional.</param>
    /// <param name="ua">The user agent of the requester, used for auditing. Optional.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/> that indicates the result of the
    /// operation. Returns a success response if the user was successfully deactivated, or a failure response if the
    /// user was not found, already inactive, or if an error occurred.</returns>
    public static ApiResult<MessageResponse> DeactivateUser(string userId, AppConfig config)
    {
        if (string.IsNullOrWhiteSpace(userId))
            return ApiResult<MessageResponse>.Fail("User ID is required", 400);
        
        try
        {
            if (!UserStore.DoesUserIdExist(userId))
                return ApiResult<MessageResponse>.Fail("User not found", 404);

            if (!UserStore.IsUserIdActive(userId))
                return ApiResult<MessageResponse>.Fail("User is already inactive", 400);

            bool deactivated = UserStore.DeactivateUser(userId);

            if (!deactivated)
                return ApiResult<MessageResponse>.Fail("User not found or already inactive", 400);

            // Revoke sessions
            UserStore.RevokeUserSessions(userId);

            // Revoke refresh tokens
            UserStore.RevokeUserRefreshTokens(userId);

            if (config.EnableAuditLogging)
                Utils.Audit.Logg(
                    action: "user_deactivated",
                    target: userId
                );

            return ApiResult<MessageResponse>.Ok(
                new MessageResponse(true, $"User '{userId}' deactivated."));
        }
        catch (Exception ex)
        {
            Log.Error($"Failed to deactivate user {userId}: {ex.Message}");
            return ApiResult<MessageResponse>.Fail("Failed to deactivate user in the database.", 500);
        }
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
        AppConfig config,
        string? ipAddress,
        string? userAgent)
    {
        if (!actingUser.HasScope(Constants.Scope_DeactivateUsers))
            return ApiResult<MessageResponse>.Forbidden("Permission Denied");

        if (string.IsNullOrWhiteSpace(targetUserId))
            return ApiResult<MessageResponse>.Fail("User ID is required");

        try
        {
            var deactivated = UserStore.DeactivateUser(targetUserId);

            if (deactivated)
                return ApiResult<MessageResponse>.NotFound("User not found or already inactive");

            // Revoke sessions
            UserStore.RevokeUserSessions(targetUserId);

            // Revoke refresh tokens
            UserStore.RevokeUserRefreshTokens(targetUserId);

            if (config.EnableAuditLogging)
                Utils.Audit.Logg(
                    action: "user_deactivated",
                    target: targetUserId
                );

            return ApiResult<MessageResponse>.Ok(new(true, $"User '{targetUserId}' deactivated."));
        }
        catch (Exception ex)
        {
            Log.Error($"Failed to deactivate user {targetUserId}: {ex.Message}");
            return ApiResult<MessageResponse>.Fail("Failed to deactivate user in the database.", 500);
        }
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
    public static ApiResult<MessageResponse> ReactivateUser(
        string userId,
        AppConfig config
    )
    {
        if (string.IsNullOrWhiteSpace(userId))
            return ApiResult<MessageResponse>.Fail("User ID is required", 400);

        try
        {
            var reactivated = UserStore.ReactivateUser(userId);

            if (reactivated)
                return ApiResult<MessageResponse>.Fail("User not found or already active", 400);

            if (config.EnableAuditLogging)
                Utils.Audit.Logg(
                    action: "user_reactivated",
                    target: userId
                );

            return ApiResult<MessageResponse>.Ok(
                new MessageResponse(true, $"User '{userId}' reactivated."));
        }
        catch (Exception ex)
        {
            Log.Error($"Failed to reactivate user {userId}: {ex.Message}");
            return ApiResult<MessageResponse>.Fail("Failed to reactivate user in the database.", 500);
        }
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
        AppConfig config
)
    {
        if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(newPassword))
            return ApiResult<MessageResponse>.Fail("User ID and new password are required", 400);

        var hash = AuthService.HashPassword(newPassword, config);

        try
        {
            var reset = UserStore.ResetUserPassword(
                userId: userId,
                newPasswordHash: hash
            );

            if (!reset)
                return ApiResult<MessageResponse>.Fail("User not found or inactive", 400);

            if (config.EnableAuditLogging)
                Utils.Audit.Logg(
                    action: "user_password_reset",
                    target: userId
                );

            return ApiResult<MessageResponse>.Ok(
                new MessageResponse(true, $"Password for user '{userId}' has been reset")
            );
        }
        catch (Exception ex)
        {
            Log.Error($"Failed to reset password for user {userId}: {ex.Message}");
            return ApiResult<MessageResponse>.Fail("Failed to reset user password in the database.", 500);
        }
    }

    /// <summary>
    /// Resets the password for a specified user, provided the acting user has the required scope.
    /// </summary>
    /// <remarks>This method updates the password hash for the specified user in the database and logs the
    /// operation for auditing purposes. The target user must be active for the operation to succeed.</remarks>
    /// <param name="actingUser">The user performing the operation. Must have the <see cref="Constants.Scope_ResetPasswords"/> scope.</param>
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
        if (!actingUser.HasScope(Constants.Scope_ResetPasswords))
            return ApiResult<MessageResponse>.Forbidden("Permission Denied");

        if (string.IsNullOrWhiteSpace(newPassword))
            return ApiResult<MessageResponse>.Fail("New password is required");

        var hash = AuthService.HashPassword(newPassword, config);

        try
        {
            var reset = UserStore.ResetUserPassword(
                userId: targetUserId,
                newPasswordHash: hash
            );

            if (reset)
                return ApiResult<MessageResponse>.NotFound("User not found or already inactive");

            if (config.EnableAuditLogging)
                Utils.Audit.Logg(
                    action: "user_password_reset",
                    target: targetUserId
                );

            return ApiResult<MessageResponse>.Ok(new(true, $"Password for user '{targetUserId}' has been reset."));
        }
        catch (Exception ex)
        {
            Log.Error($"Failed to reset password for user {targetUserId}: {ex.Message}");
            return ApiResult<MessageResponse>.Fail("Failed to reset user password in the database.", 500);
        }
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
        try
        {
            UserStore.WriteSessionToDb(token, clientIdent);
        }
        catch (Exception ex)
        {
            Log.Error($"Failed to write session {token.Jti} for user {token.UserId} to database: {ex.Message}");
            throw; // Re-throw the exception to be handled by the caller
        }
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
    public static ApiResult<List<SessionResponse>> ListSessions()
    {
        try
        {
            var sessions = UserStore.ListSessions();
            return ApiResult<List<SessionResponse>>.Ok(sessions);
        }
        catch (Exception ex)
        {
            Log.Error($"Failed to load sessions: {ex.Message}");
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

        try
        {
            var session = UserStore.GetSessionById(jti);

            if (session is null)
                return ApiResult<SessionResponse>.NotFound("Session not found");

            return ApiResult<SessionResponse>.Ok(session);
        }
        catch (Exception ex)
        {
            Log.Error($"Failed to retrieve session {jti}: {ex.Message}");
            return ApiResult<SessionResponse>.Fail("Failed to retrieve session from the database.", 500);
        }        
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
            var sessions = UserStore.GetSessionsByUserId(userId);
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
        return GetSessionsByUserId(userId);
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

        try
        {
            var tokens = UserStore.GetRefreshTokensByUserId(userId);
            return ApiResult<List<RefreshTokenResponse>>.Ok(tokens);
        }
        catch (Exception ex)
        {
            Log.Error($"Failed to retrieve refresh tokens for user {userId}: {ex.Message}");
            return ApiResult<List<RefreshTokenResponse>>.Fail("Failed to retrieve refresh tokens from the database.", 500);
        }        
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
    public static ApiResult<RevokeResponse> RevokeSessionById(string jti, AppConfig config)
    {
        if (string.IsNullOrWhiteSpace(jti))
            return ApiResult<RevokeResponse>.Fail("Missing JTI", 400);

        try
        {
            (bool revoked, string message, string userId) = UserStore.RevokeSessionById(jti);

            if (config.EnableAuditLogging)
                Utils.Audit.Logg(
                    action: "session_revoked",
                    target: jti,
                    secondary: userId
                );

            if (!revoked)
            {
                return ApiResult<RevokeResponse>.Fail(message, 400);
            }

            return ApiResult<RevokeResponse>.Ok(new RevokeResponse
            {
                Status = "revoked",
                Jti = jti,
                Message = message
            });
        }
        catch (Exception ex)
        {
            Log.Error($"Failed to revoke session {jti}: {ex.Message}");
            return ApiResult<RevokeResponse>.Fail("Failed to revoke session in the database.", 500);
        }
    }


    /// <summary>
    /// Purges user sessions from the database based on specified conditions.
    /// </summary>
    /// <remarks>This method allows selective purging of user sessions based on their expiration status,
    /// revocation status, or both. If neither <paramref name="purgeExpired"/> nor <paramref name="purgeRevoked"/> is
    /// <see langword="true"/>, no sessions will be purged, and the method will return a message indicating that no
    /// action was taken. Audit logging is performed for all purge operations, including details about the number of
    /// sessions purged and the conditions used.</remarks>
    /// <param name="cutoffUtc">The time span used to determine the cutoff for expired sessions. Sessions older than this value will be
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
    DateTime cutoffUtc,
    bool purgeExpired,
    bool purgeRevoked,
    AppConfig config)
    {
        try
        {
            (bool success, int purged) = UserStore.PurgeSessions(
                olderThanUtc: cutoffUtc,
                purgeExpired: purgeExpired,
                purgeRevoked: purgeRevoked
            );

            if (config.EnableAuditLogging)
                Utils.Audit.Logg(
                    action: "sessions_purged",
                    target: $"purged={purged};expired={purgeExpired};revoked={purgeRevoked}"
                );

            return ApiResult<MessageResponse>.Ok(new(true, $"Purged {purged} session(s)."));
        }
        catch (Exception ex)
        {
            Log.Error($"Failed to purge sessions: {ex.Message}");
            return ApiResult<MessageResponse>.Fail("Failed to purge sessions in the database.", 500);
        }
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
        var expires = DateTime.UtcNow.AddSeconds(config.RefreshTokenExpiration);

        var id = Guid.NewGuid().ToString();

        var sha256 = Utils.Sha256Base64(raw);

        // We do not store the raw token, only the argon2id hash and its SHA-256 for quick lookup
        UserStore.StoreRefreshToken(
            id: id,
            userId: userId,
            sessionId: sessionId,
            clientIdent: clientIdent,
            sha256Hash: sha256,
            expires: expires
        );

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
    public static ApiResult<List<RefreshTokenResponse>> ListRefreshTokens()
    {
        try
        {
            var tokens = UserStore.ListRefreshTokens();
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

        try
        {
            var token = UserStore.GetRefreshTokenById(tokenId);

            if (token is null)
                return ApiResult<RefreshTokenResponse>.NotFound("Refresh token not found");

            return ApiResult<RefreshTokenResponse>.Ok(token);
        }
        catch (Exception ex)
        {
            Log.Error($"Failed to retrieve refresh token {tokenId}: {ex.Message}");
            return ApiResult<RefreshTokenResponse>.Fail("Failed to retrieve refresh token from the database.", 500);
        }
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
            var tokens = UserStore.GetRefreshTokensByUserId(userId);
            return ApiResult<List<RefreshTokenResponse>>.Ok(tokens);
        }
        catch (Exception ex)
        {
            Log.Error($"Failed to retrieve refresh tokens for user {userId}: {ex.Message}");
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
        AppConfig config)
    {
        try
        {
            var span = TimeSpan.FromSeconds(req.OlderThanSeconds);
            var cutoffUtc = DateTime.UtcNow - span;

            (bool success, int purged) = UserStore.PurgeRefreshTokens(
                olderThanUtc: cutoffUtc,
                purgeExpired: req.PurgeExpired,
                purgeRevoked: req.PurgeRevoked
            );

            if (config.EnableAuditLogging)
                Utils.Audit.Logg(
                    action: "refresh_tokens_purged",
                    target: $"purged={purged};expired={req.PurgeExpired};revoked={req.PurgeRevoked}"
                );

            return ApiResult<MessageResponse>.Ok(new(true, $"Purged {purged} refresh token(s)."));
        }
        catch (Exception ex)
        {
            Log.Error($"Failed to purge refresh tokens: {ex.Message}");
            return ApiResult<MessageResponse>.Fail("Failed to purge refresh tokens in the database.", 500);
        }
    }

    /// <summary>
    /// Generates a Time-based One-Time Password (TOTP) secret for the specified user and creates a QR code in SVG
    /// format for the user to scan with an authenticator app.
    /// </summary>
    /// <remarks>This method performs the following steps: <list type="bullet"> <item>Validates that the user
    /// exists and is active in the database.</item> <item>Generates a new TOTP secret for the user.</item>
    /// <item>Creates a QR code in SVG format containing the TOTP secret and saves it to the specified output
    /// path.</item> <item>Updates the user's record in the database with the new TOTP secret.</item> </list> The
    /// generated QR code can be scanned by the user using an authenticator app (e.g., Google Authenticator) to set up
    /// TOTP-based authentication.</remarks>
    /// <param name="userId">The unique identifier of the user for whom the TOTP secret is being generated. Must refer to an active user.</param>
    /// <param name="outputPath">The directory path where the generated QR code SVG file will be saved. Must be a valid, writable path.</param>
    /// <param name="config">The application configuration object containing necessary settings for the operation.</param>
    /// <returns>An <see cref="ApiResult{TotpQrResponse}"/> containing the result of the operation. If successful, the result
    /// includes the filename of the generated QR code. If the user is not found, the result indicates a "Not Found"
    /// status.</returns>
    public static ApiResult<TotpQrResponse> GenerateTotpForUser(
        string userId,
        string outputPath,
        AppConfig config)
    {
        try
        {
            var user = UserStore.GetUsernameById(userId);

            if (user is null)
                return ApiResult<TotpQrResponse>.NotFound("User not found");

            // Generate new TOTP secret
            var secret = Utils.GenerateBase32Secret();
            var uri = $"otpauth://totp/microauthd:{user}?secret={secret}&issuer=microauthd";

            // Generate filename
            var filename = $"totp_qr_{Utils.RandHex(6)}.svg";
            var fullPath = Path.Combine(outputPath, filename);

            // Create SVG QR
            var qrGen = new QRCodeGenerator();
            var data = qrGen.CreateQrCode(uri, QRCodeGenerator.ECCLevel.Q);
            var svgQr = new SvgQRCode(data).GetGraphic(5);
            File.WriteAllText(fullPath, svgQr);

            UserStore.StoreTotpSecret(
                userId: userId,
                otpSecret: secret
            );

            return ApiResult<TotpQrResponse>.Ok(new TotpQrResponse
            {
                Success = true,
                Filename = filename
            });
        }
        catch (Exception ex)
        {
            Log.Error($"Failed to generate TOTP for user {userId}: {ex.Message}");
            return ApiResult<TotpQrResponse>.Fail("Failed to generate TOTP secret", 500);
        }
    }

    /// <summary>
    /// Verifies a Time-based One-Time Password (TOTP) code for a user and enables TOTP for the user if the code is
    /// valid.
    /// </summary>
    /// <remarks>This method performs the following steps: <list type="bullet"> <item><description>Validates
    /// the input parameters.</description></item> <item><description>Retrieves the user's TOTP secret from the database
    /// if the user is active.</description></item> <item><description>Verifies the provided TOTP code against the
    /// user's secret.</description></item> <item><description>Enables TOTP for the user in the database if the code is
    /// valid.</description></item> </list> Possible failure scenarios include: <list type="bullet">
    /// <item><description>Missing or invalid input parameters.</description></item> <item><description>User not found,
    /// inactive, or missing a TOTP secret.</description></item> <item><description>Invalid TOTP
    /// code.</description></item> <item><description>Database update failure when enabling TOTP.</description></item>
    /// </list></remarks>
    /// <param name="userId">The unique identifier of the user. Cannot be null, empty, or whitespace.</param>
    /// <param name="code">The TOTP code to verify. Cannot be null, empty, or whitespace.</param>
    /// <param name="config">The application configuration object used for database and other settings.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/> that indicates the result of the
    /// operation. Returns a success response if the TOTP code is valid and TOTP is successfully enabled for the user.
    /// Returns a failure response with an appropriate status code and message if the operation fails.</returns>
    public static ApiResult<MessageResponse> VerifyTotpCode(string userId, string code, AppConfig config)
    {
        if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(code))
            return ApiResult<MessageResponse>.Fail("totp failure", 403);

        try
        {
            var otpSecret = UserStore.GetTotpSecretByUserId(userId);

            if (string.IsNullOrWhiteSpace(otpSecret))
                return ApiResult<MessageResponse>.Fail("totp failure", 403);

            var totp = new OtpNet.Totp(Base32Encoding.ToBytes(otpSecret));
            if (!totp.VerifyTotp(code, out _, new VerificationWindow(1, 1)))
                return ApiResult<MessageResponse>.Fail("totp failure", 403);

            var affected = UserStore.EnableTotpForUserId(userId);

            if (affected > 0)
                return ApiResult<MessageResponse>.Ok(new(true, "TOTP enabled for user"));

            return ApiResult<MessageResponse>.Fail("totp failure", 403);
        }
        catch (Exception ex)
        {
            Log.Error($"Failed to verify TOTP code for user {userId}: {ex.Message}");
            return ApiResult<MessageResponse>.Fail("Failed to verify TOTP code", 500);
        }
    }

    /// <summary>
    /// Disables Time-based One-Time Password (TOTP) authentication for the specified user.
    /// </summary>
    /// <remarks>This method updates the user's record in the database to disable TOTP authentication by
    /// setting the `totp_enabled` field to 0  and clearing the `totp_secret`. If the user is not found or is already
    /// inactive, the method returns a failure response with a 404 status code. An audit log entry is created for the
    /// operation.</remarks>
    /// <param name="userId">The unique identifier of the user for whom TOTP authentication will be disabled. Cannot be null, empty, or
    /// whitespace.</param>
    /// <param name="config">The application configuration used for logging and other operations. Must not be null.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/> that indicates the result of the
    /// operation. Returns a success response if TOTP was successfully disabled, or a failure response with an
    /// appropriate error message and status code.</returns>
    public static ApiResult<MessageResponse> DisableTotpForUser(string userId, AppConfig config)
    {
        if (string.IsNullOrWhiteSpace(userId))
            return ApiResult<MessageResponse>.Fail("Missing user_id", 400);

        try
        {
            var affected = UserStore.DisableTotpForUserId(userId);

            if (affected == 0)
                return ApiResult<MessageResponse>.Fail("User not found or already inactive", 404);

            if (config.EnableAuditLogging) 
                Utils.Audit.Logg("disable_totp", userId);

            return ApiResult<MessageResponse>.Ok(new(true, "TOTP disabled for user"));
        }
        catch (Exception ex)
        {
            Log.Error($"Failed to disable TOTP for user {userId}: {ex.Message}");
            return ApiResult<MessageResponse>.Fail("Failed to disable TOTP for user", 500);
        }
    }

    /// <summary>
    /// Replaces the scope assignments for a specified user with the provided set of scopes.
    /// </summary>
    /// <remarks>This method updates the scope assignments for the specified user by comparing the current
    /// scopes with the provided scopes. Scopes that are not currently assigned but are included in the provided list
    /// are added, while scopes that are currently assigned but not included in the provided list are removed. Both
    /// addition and removal operations are internally audit logged.</remarks>
    /// <param name="dto">The data transfer object containing the target user ID and the list of scopes to assign. The <see
    /// cref="ScopeAssignmentDto.TargetId"/> must not be null or whitespace.</param>
    /// <param name="config">The application configuration used for scope assignment operations.</param>
    /// <param name="actorUserId">The ID of the user performing the operation. This is used for audit logging.</param>
    /// <param name="ip">The IP address of the actor user, used for audit logging. Can be null.</param>
    /// <param name="ua">The user agent string of the actor user, used for audit logging. Can be null.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/> that indicates whether the operation
    /// was successful. If successful, the response contains a success message. If validation fails, the response
    /// contains an error message and a 400 status code.</returns>
    public static ApiResult<MessageResponse> ReplaceUserScopes(
            ScopeAssignmentDto dto,
            AppConfig config,
            string actorUserId,
            string? ip,
            string? ua)
    {
        if (string.IsNullOrWhiteSpace(dto.TargetId))
            return ApiResult<MessageResponse>.Fail("Missing targetId", 400);

        var current = ScopeStore.GetAssignedScopesForUser(dto.TargetId)
            .Select(r => r.Id)
            .ToHashSet();

        var submitted = dto.Scopes
            .Where(r => !string.IsNullOrWhiteSpace(r.Id))
            .Select(r => r.Id)
            .ToHashSet();

        var toAdd = submitted.Except(current).ToList();
        var toRemove = current.Except(submitted).ToList();

        // AddScopeToUser and RemoveScopeFromUser are both audit logged internally,
        // so we don't need to log here again as it's redundant.
        AssignScopesRequest req = new();
        req.ScopeIds.AddRange(toAdd);
        ScopeService.AddScopesToUser(dto.TargetId, req, config);

        foreach (var scopeId in toRemove)
            ScopeService.RemoveScopeFromUser(dto.TargetId, scopeId, config);

        return ApiResult<MessageResponse>.Ok(new MessageResponse(true, "Scopes updated."));
    }

    /// <summary>
    /// Sets or clears the lockout period for a specified user.
    /// </summary>
    /// <remarks>This method logs the action for auditing purposes and handles any exceptions that occur
    /// during the operation. If an error occurs, the method returns a failure result with an appropriate error message
    /// and HTTP status code.</remarks>
    /// <param name="userId">The unique identifier of the user for whom the lockout period is being set or cleared.</param>
    /// <param name="until">The date and time until which the user is locked out.  Specify <see langword="null"/> to clear the lockout
    /// period.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/> that indicates whether the operation
    /// was successful. If successful, the response includes a message describing the action performed.</returns>
    public static ApiResult<MessageResponse> SetLockout(string userId, DateTime? until, AppConfig config)
    {
        try
        {
            UserStore.SetUserLockoutUntil(userId, until);

            if (config.EnableAuditLogging)
                Utils.Audit.Logg(
                    action: until == null ? "admin.lockout.clear" : "admin.lockout.set",
                    target: userId,
                    secondary: until?.ToString("o") ?? "(cleared)"
                );

            // If lockout is set, revoke all sessions and refresh tokens for the user
            if (until is not null)
            {
                UserStore.RevokeUserSessions(userId);
                UserStore.RevokeUserRefreshTokens(userId);
            }

            return ApiResult<MessageResponse>.Ok(
                new MessageResponse(true, $"User lockout {(until == null ? "cleared" : "set to " + until.Value.ToString("u"))}")
            );
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to set lockout for user {UserId}", userId);
            return ApiResult<MessageResponse>.Fail("Internal server error", 500);
        }
    }

    /// <summary>
    /// Retrieves the total number of users currently stored in the system.
    /// </summary>
    /// <returns>The total count of users as an integer. Returns 0 if no users are stored.</returns>
    public static int GetUserCount() => UserStore.GetUserCount();

    /// <summary>
    /// Retrieves the total number of inactive users in the system.
    /// </summary>
    /// <returns>The number of users who are marked as inactive. Returns 0 if there are no inactive users.</returns>
    public static int GetInactiveUserCount() => UserStore.GetInactiveUserCount();

    /// <summary>
    /// Retrieves the total number of active user sessions.
    /// </summary>
    /// <returns>The total count of active user sessions. Returns 0 if there are no active sessions.</returns>
    public static int GetUserSessionCount() => UserStore.GetUserSessionCount();

    /// <summary>
    /// Retrieves the number of active user sessions currently tracked by the system.
    /// </summary>
    /// <returns>The total count of active user sessions. Returns 0 if no active sessions are found.</returns>
    public static int GetActiveUserSessionCount() => UserStore.GetActiveUserSessionCount();
}
