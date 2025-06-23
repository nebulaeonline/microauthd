using madTypes.Api.Common;
using madTypes.Api.Requests;
using madTypes.Api.Responses;
using madTypes.Common;
using microauthd.Common;
using microauthd.Config;
using microauthd.Data;
using Microsoft.Data.Sqlite;
using nebulae.dotArgon2;
using Serilog;
using System.Security.Claims;
using System.Text;
using static nebulae.dotArgon2.Argon2;

namespace microauthd.Services;

public static class RoleService
{
    /// <summary>
    /// Creates a new role with the specified name and optional description.
    /// </summary>
    /// <param name="name">The name of the role to create. This value cannot be null, empty, or whitespace.</param>
    /// <param name="description">An optional description for the role. If null, an empty string will be used.</param>
    /// <param name="userId">An optional identifier for the user performing the operation. Used for audit logging.</param>
    /// <param name="ip">An optional IP address of the user performing the operation. Used for audit logging.</param>
    /// <param name="ua">An optional user agent string of the user performing the operation. Used for audit logging.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/>.  If the operation succeeds, the result
    /// indicates success and includes a message confirming the role creation. If the operation fails, the result
    /// indicates failure and includes an error message.</returns>
    public static ApiResult<RoleObject> CreateRole(
        string name,
        string? description,
        AppConfig config,
        string? userId = null,
        string? ip = null,
        string? ua = null)
    {
        if (string.IsNullOrWhiteSpace(name))
            return ApiResult<RoleObject>.Fail("Role name is required");

        try
        {
            var roleId = Guid.NewGuid().ToString();

            var role = RoleStore.CreateRole(roleId, name, description ?? string.Empty);

            if (role is null)
                return ApiResult<RoleObject>.Fail("Role created but could not be retrieved from the database.");

            Utils.Audit.Logg(
                action: "role_created",
                target: name
            );

            return ApiResult<RoleObject>.Ok(role);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to create role {RoleName}", name);
            return ApiResult<RoleObject>.Fail("Failed to create role", 500);
        }
    }

    /// <summary>
    /// Updates an existing role with the specified details.
    /// </summary>
    /// <remarks>The method enforces the following constraints: <list type="bullet"> <item><description>The
    /// <paramref name="updated"/> object must have a valid <see cref="RoleObject.Name"/> that is not null or
    /// whitespace.</description></item> <item><description>Roles cannot be marked as protected through this
    /// API.</description></item> <item><description>The role name must be unique among all roles except the one being
    /// updated.</description></item> </list> If the role is protected or does not exist, the update will fail. The
    /// method also retrieves the updated role from the database after a successful update.</remarks>
    /// <param name="id">The unique identifier of the role to update.</param>
    /// <param name="updated">An object containing the updated role details. The <see cref="RoleObject.Name"/> property must not be null or
    /// whitespace.</param>
    /// <param name="config">The application configuration used for database access and other settings.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing the updated <see cref="RoleObject"/> if the operation succeeds;
    /// otherwise, an error message describing the failure.</returns>
    public static ApiResult<RoleObject> UpdateRole(
        string id,
        RoleObject updated,
        AppConfig config
    )
    {
        if (updated.IsProtected)
            return ApiResult<RoleObject>.Fail("Cannot mark a role as protected through this API.");

        try
        {
            // Check for name collision only if name is being updated
            if (!string.IsNullOrWhiteSpace(updated.Name))
            {
                var conflict = RoleStore.DoesNameConflictExist(id, updated.Name);

                if (conflict)
                    return ApiResult<RoleObject>.Fail("Another role already uses that name.");
            }

            // Perform the update dynamically
            var updatedRole = RoleStore.UpdateRole(id, updated);

            if (updatedRole is null)
                return ApiResult<RoleObject>.Fail("Role update failed. Role may be protected or not found.");

            return ApiResult<RoleObject>.Ok(updatedRole);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to update role {RoleId}", id);
            return ApiResult<RoleObject>.Fail("Failed to update role", 500);
        }
    }

    /// <summary>
    /// Retrieves a list of all active role names from the database.
    /// </summary>
    /// <remarks>The roles are returned in ascending order by name. Only roles marked as active in the
    /// database are included in the result.</remarks>
    /// <returns>An <see cref="ApiResult{T}"/> containing a list of active role names. The list will be empty if no active roles
    /// are found.</returns>
    public static ApiResult<List<RoleObject>> ListAllRoles()
    {
        try
        {
            var roles = RoleStore.ListAllRoles();

            return ApiResult<List<RoleObject>>.Ok(roles);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to retrieve all roles");
            return ApiResult<List<RoleObject>>.Fail("Unable to retrieve roles", 500);
        }
    }

    /// <summary>
    /// Retrieves a role by its unique identifier.
    /// </summary>
    /// <remarks>This method queries the database for a role with the specified identifier. If the role is
    /// found, it is returned as part of a successful result. Otherwise, a "Not Found" result is returned. The role
    /// object includes details such as the role's name, description, and protection status.</remarks>
    /// <param name="id">The unique identifier of the role to retrieve. Cannot be null or empty.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing the role object if found, or a "Not Found" result if no role exists
    /// with the specified identifier.</returns>
    public static ApiResult<RoleObject> GetRoleById(string id)
    {
        try
        {
            var role = RoleStore.GetRoleById(id);

            return role is null
                ? ApiResult<RoleObject>.NotFound($"Role '{id}' not found.")
                : ApiResult<RoleObject>.Ok(role);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Error retrieving role by ID: {RoleId}", id);
            return ApiResult<RoleObject>.Fail("Internal error occurred", 500);
        }
    }

    /// <summary>
    /// Retrieves the unique identifier of a role based on its name.
    /// </summary>
    /// <remarks>This method attempts to retrieve the role ID from the underlying role store. If the role name
    /// is invalid or the role does not exist, an appropriate error result is returned. In the event of an internal
    /// error, a generic failure result is returned with a status code of 500.</remarks>
    /// <param name="name">The name of the role to look up. This parameter cannot be null, empty, or consist solely of whitespace.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing the role's unique identifier if found, or an error message and status
    /// code if the role is not found or an error occurs.</returns>
    public static ApiResult<string> GetRoleIdByName(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
            return ApiResult<string>.Fail("Role name is required", 400);

        try
        {
            var id = RoleStore.GetRoleIdByName(name);

            return id == null
                ? ApiResult<string>.Fail("Role not found", 404)
                : ApiResult<string>.Ok(id);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Error retrieving role ID by name");
            return ApiResult<string>.Fail("Internal error occurred", 500);
        }
    }

    /// <summary>
    /// Assigns a specified role to a user in the system.
    /// </summary>
    /// <remarks>This method performs the following steps: <list type="bullet"> <item><description>Validates
    /// that the <paramref name="userId"/> and <paramref name="roleId"/> are not null or
    /// whitespace.</description></item> <item><description>Checks the existence of the specified user and role in the
    /// database.</description></item> <item><description>Assigns the role to the user by inserting a record into the
    /// user_roles table.</description></item> <item><description>Logs the operation in the audit log, if <paramref
    /// name="actorId"/>, <paramref name="ip"/>, or <paramref name="ua"/> are provided.</description></item>
    /// </list></remarks>
    /// <param name="userId">The unique identifier of the user to whom the role will be assigned. Cannot be null or whitespace.</param>
    /// <param name="roleId">The unique identifier of the role to assign to the user. Cannot be null or whitespace.</param>
    /// <param name="config">The application configuration used to establish the database connection.</param>
    /// <param name="actorId">The unique identifier of the actor performing the operation. This is used for audit logging purposes. Optional;
    /// can be null if no actor information is available.</param>
    /// <param name="ip">The IP address of the actor performing the operation. This is used for audit logging purposes. Optional; can be
    /// null if no IP address is available.</param>
    /// <param name="ua">The user agent string of the actor performing the operation. This is used for audit logging purposes. Optional;
    /// can be null if no user agent information is available.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/> that indicates the result of the
    /// operation. Returns a success result if the role is successfully assigned to the user, or a failure result with
    /// an error message if the operation fails (e.g., if the user or role is not found, or if required parameters are
    /// invalid).</returns>
    public static ApiResult<MessageResponse> AddRoleToUser(
        string userId,
        string roleId,
        AppConfig config,
        string? actorId = null,
        string? ip = null,
        string? ua = null)
    {
        if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(roleId))
            return ApiResult<MessageResponse>.Fail("User Id and Role Id are required");

        try
        {
            var added = RoleStore.AddRoleToUser(userId, roleId);

            if (!added)
                return ApiResult<MessageResponse>.Fail("Failed to assign role (user or role not found, or already assigned)");

            Utils.Audit.Logg(
                action: "role_assigned",
                target: userId,
                secondary: roleId
            );

            return ApiResult<MessageResponse>.Ok(new(true, $"Assigned role '{roleId}' to user '{userId}'"));
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to assign role {RoleId} to user {UserId}", roleId, userId);
            return ApiResult<MessageResponse>.Fail("Failed to assign role", 500);
        }
    }

    /// <summary>
    /// Retrieves a list of active roles assigned to a specified user.
    /// </summary>
    /// <remarks>The method queries the database for roles that are both active and associated with the
    /// specified user.  Roles are returned in ascending order by name. The operation will fail if the <paramref
    /// name="userId"/> is not provided.</remarks>
    /// <param name="userId">The unique identifier of the user whose roles are to be retrieved. Cannot be null, empty, or whitespace.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a list of role names assigned to the user.  If the user has no active
    /// roles, the list will be empty. If the <paramref name="userId"/> is invalid, the result will indicate failure.</returns>
    public static ApiResult<List<string>> ListRolesForUser(string userId)
    {
        if (string.IsNullOrWhiteSpace(userId))
            return ApiResult<List<string>>.Fail("User Id is required");

        try
        {
            var roles = RoleStore.GetUserRoles(userId);

            return ApiResult<List<string>>.Ok(roles);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to retrieve roles for user {UserId}", userId);
            return ApiResult<List<string>>.Fail("Unable to retrieve user roles", 500);
        }
    }

    /// <summary>
    /// Deletes a role from the database by its unique identifier.
    /// </summary>
    /// <remarks>This method performs an audit log entry if the deletion is successful. If the role cannot be
    /// deleted due to database constraints or if it does not exist, the method returns a failure result.</remarks>
    /// <param name="roleId">The unique identifier of the role to delete. Cannot be null or empty.</param>
    /// <param name="config">The application configuration used for logging and auditing. Cannot be null.</param>
    /// <param name="userId">The optional identifier of the user performing the operation, used for auditing purposes.</param>
    /// <param name="ip">The optional IP address of the user performing the operation, used for auditing purposes.</param>
    /// <param name="ua">The optional user agent string of the user performing the operation, used for auditing purposes.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/> that indicates the result of the
    /// operation. Returns a success result if the role was deleted, or a failure result if the role was not found or a
    /// constraint violation occurred.</returns>
    public static ApiResult<MessageResponse> DeleteRole(
    string roleId,
    AppConfig config,
    string? userId = null,
    string? ip = null,
    string? ua = null)
    {
        try
        {
            var deleted = RoleStore.DeleteRole(roleId);

            if (!deleted)
                return ApiResult<MessageResponse>.Fail("Failed to delete role (not found or constraint violation)");

            Utils.Audit.Logg("delete_role", roleId);
            return ApiResult<MessageResponse>.Ok(new(true, $"Role '{roleId}' deleted"));
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to delete role {RoleId}", roleId);
            return ApiResult<MessageResponse>.Fail("Failed to delete role", 500);
        }
    }
    
    /// <summary>
    /// Removes a specified role from a user in the system.
    /// </summary>
    /// <remarks>This method removes the association between a user and a role in the system. If the specified
    /// user or role does not exist, or if the role is not currently assigned to the user, the operation will fail.  The
    /// method also logs an audit entry for the operation if an <paramref name="actorId"/> is provided.</remarks>
    /// <param name="userId">The unique identifier of the user from whom the role will be removed. Cannot be null or whitespace.</param>
    /// <param name="roleId">The unique identifier of the role to be removed. Cannot be null or whitespace.</param>
    /// <param name="config">The application configuration used to establish the database connection.</param>
    /// <param name="actorId">The unique identifier of the actor performing the operation. Optional.</param>
    /// <param name="ip">The IP address of the actor performing the operation. Optional.</param>
    /// <param name="ua">The user agent string of the actor performing the operation. Optional.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/> that indicates the result of the
    /// operation. Returns a success result if the role was successfully removed, or a failure result with an
    /// appropriate error message if the operation could not be completed.</returns>
    public static ApiResult<MessageResponse> RemoveRoleFromUser(
        string userId,
        string roleId,
        AppConfig config,
        string? actorId = null,
        string? ip = null,
        string? ua = null)
    {
        if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(roleId))
            return ApiResult<MessageResponse>.Fail("User Id and Role Id are required");

        try
        {
            var removed = RoleStore.RemoveRoleFromUser(userId, roleId);

            if (!removed)
                return ApiResult<MessageResponse>.Fail("Failed to remove role (user or role not found, or not assigned)");

            Utils.Audit.Logg(
                action: "role_unassigned",
                target: userId,
                secondary: roleId
            );

            return ApiResult<MessageResponse>.Ok(
                new(true, $"Removed role '{roleId}' from user '{userId}'"));
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to remove role {RoleId} from user {UserId}", roleId, userId);
            return ApiResult<MessageResponse>.Fail("Failed to remove role", 500);
        }
    }

    /// <summary>
    /// Replaces the roles assigned to a user with a new set of roles.
    /// </summary>
    /// <remarks>This method updates the roles assigned to a user by comparing the current roles with the
    /// provided roles. Roles that are not in the new set are removed, and roles that are in the new set but not
    /// currently assigned are added. Audit logging is performed to record the changes.</remarks>
    /// <param name="dto">An object containing the user ID and the new set of roles to assign. The <see cref="RoleAssignmentDto.UserId"/>
    /// property must not be null or whitespace, and each role in <see cref="RoleAssignmentDto.Roles"/> must have a
    /// valid ID.</param>
    /// <param name="config">The application configuration used for role assignment and audit logging.</param>
    /// <param name="actorUserId">The ID of the user performing the operation. This is used for audit logging.</param>
    /// <param name="ip">The IP address of the user performing the operation. This is used for audit logging. Can be null.</param>
    /// <param name="ua">The user agent string of the user performing the operation. This is used for audit logging. Can be null.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/> that indicates the success or failure
    /// of the operation. If successful, the response contains a message confirming that the roles were updated.</returns>
    public static ApiResult<MessageResponse> ReplaceUserRoles(
        RoleAssignmentDto dto,
        AppConfig config,
        string actorUserId,
        string? ip,
        string? ua)
    {
        if (string.IsNullOrWhiteSpace(dto.UserId))
            return ApiResult<MessageResponse>.Fail("Missing userId", 400);

        var current = RoleStore.GetAssignedRolesDto(dto.UserId)
            .Select(r => r.Id)
            .ToHashSet();

        var submitted = dto.Roles
            .Where(r => !string.IsNullOrWhiteSpace(r.Id))
            .Select(r => r.Id)
            .ToHashSet();

        var toAdd = submitted.Except(current).ToList();
        var toRemove = current.Except(submitted).ToList();

        // AddRoleToUser and RemoveRoleFromUser are both audit logged internally,
        // so we don't need to log here again as it's redundant.
        foreach (var roleId in toAdd)
            AddRoleToUser(dto.UserId, roleId, config, actorUserId, ip, ua);

        foreach (var roleId in toRemove)
            RemoveRoleFromUser(dto.UserId, roleId, config, actorUserId, ip, ua);

        return ApiResult<MessageResponse>.Ok(new MessageResponse(true, "Roles updated."));
    }

    /// <summary>
    /// Retrieves a list of all roles as data transfer objects (DTOs).
    /// </summary>
    /// <remarks>This method returns a result containing all roles available in the system. If the operation
    /// fails, an error message and status code are included in the result.</remarks>
    /// <returns>An <see cref="ApiResult{T}"/> containing a list of <see cref="RoleDto"/> objects representing all roles. If the
    /// operation fails, the result contains an error message and a status code.</returns>
    public static ApiResult<List<RoleDto>> GetAllRoleDtos()
    {
        try
        {
            var roles = RoleStore.GetAllRoleDtos();
            return ApiResult<List<RoleDto>>.Ok(roles);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to retrieve all roles");
            return ApiResult<List<RoleDto>>.Fail("Unable to retrieve roles", 500);
        }
    }

    /// <summary>
    /// Retrieves the list of roles assigned to a specific user.
    /// </summary>
    /// <remarks>This method attempts to retrieve the roles assigned to the specified user from the underlying
    /// role store. If the operation is successful, the result will contain the list of roles. If an error occurs during
    /// retrieval, the result will include an error message and a status code indicating the failure.</remarks>
    /// <param name="userId">The unique identifier of the user whose assigned roles are to be retrieved. Must not be null, empty, or consist
    /// solely of whitespace.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a list of <see cref="RoleDto"/> objects representing the user's
    /// assigned roles. If the operation fails, the result will include an error message and an appropriate HTTP status
    /// code.</returns>
    public static ApiResult<List<RoleDto>> GetAssignedRolesDto(string userId)
    {
        if (string.IsNullOrWhiteSpace(userId))
            return ApiResult<List<RoleDto>>.Fail("Missing userId", 400);

        try
        {
            var roles = RoleStore.GetAssignedRolesDto(userId);
            return ApiResult<List<RoleDto>>.Ok(roles);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to retrieve assigned roles for user {UserId}", userId);
            return ApiResult<List<RoleDto>>.Fail("Unable to retrieve user roles", 500);
        }
    }

    /// <summary>
    /// Retrieves the total number of roles currently stored in the system.
    /// </summary>
    /// <returns>The total count of roles as an integer. Returns 0 if no roles are stored.</returns>
    public static int GetRoleCount() => RoleStore.GetRoleCount();
}
