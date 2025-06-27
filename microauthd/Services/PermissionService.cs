using madTypes.Api.Common;
using madTypes.Api.Responses;
using madTypes.Common;
using microauthd.Common;
using microauthd.Config;
using microauthd.Data;
using Microsoft.Data.Sqlite;
using Serilog;

namespace microauthd.Services
{
    public static class PermissionService
    {
        /// <summary>
        /// Creates a new permission with the specified name and logs the operation.
        /// </summary>
        /// <remarks>This method attempts to create a new permission in the database. If a permission with the
        /// same name already exists,  the operation will fail, and an appropriate error message will be returned.
        /// Additionally, an audit log entry is created  for the operation if <paramref name="userId"/> is
        /// provided.</remarks>
        /// <param name="name">The name of the permission to create. This value cannot be null, empty, or whitespace.</param>
        /// <param name="userId">The ID of the user performing the operation. This value can be null if the user is not authenticated.</param>
        /// <param name="ip">The IP address of the user performing the operation. This value is optional and can be null.</param>
        /// <param name="ua">The user agent string of the user performing the operation. This value is optional and can be null.</param>
        /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/>.  If the operation succeeds, the result
        /// is successful and contains a message indicating the permission was created.  If the operation fails (e.g., due
        /// to a duplicate name), the result is a failure with an appropriate error message.</returns>
        public static ApiResult<PermissionObject> CreatePermission(
            string name,
            AppConfig config)
        {
            if (string.IsNullOrWhiteSpace(name))
                return ApiResult<PermissionObject>.Fail("Permission name is required");

            var permissionId = Guid.NewGuid().ToString();

            try
            {
                var permissionObj = PermissionStore.CreatePermission(permissionId, name);

                if (permissionObj is null)
                    return ApiResult<PermissionObject>.Fail("Permission creation failed (maybe duplicate?)");

                if (config.EnableAuditLogging) 
                    Utils.Audit.Logg("create_permission", name);

                return ApiResult<PermissionObject>.Ok(permissionObj);
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Failed to create permission with name {Name}", name);
                return ApiResult<PermissionObject>.Fail("Permission creation failed (maybe duplicate?)");
            }
        }

        /// <summary>
        /// Updates an existing permission with the specified details.
        /// </summary>
        /// <remarks>This method performs the following validations and operations: <list type="bullet">
        /// <item><description>Ensures the <paramref name="updated"/> permission name is not null, empty, or
        /// whitespace.</description></item> <item><description>Checks for conflicts with existing permissions that have the
        /// same name but a different ID.</description></item> <item><description>Updates the permission in the database if
        /// no conflicts are found.</description></item> <item><description>Retrieves and returns the updated permission
        /// record upon success.</description></item> </list> Possible failure reasons include invalid input, name
        /// conflicts, or database update errors.</remarks>
        /// <param name="id">The unique identifier of the permission to update.</param>
        /// <param name="updated">The updated permission details. The <see cref="PermissionObject.Name"/> property must not be null, empty, or
        /// whitespace.</param>
        /// <param name="config">The application configuration used for database access and other settings.</param>
        /// <returns>An <see cref="ApiResult{T}"/> containing the updated <see cref="PermissionObject"/> if the operation succeeds;
        /// otherwise, an error message indicating the reason for failure.</returns>
        public static ApiResult<PermissionObject> UpdatePermission(
            string id,
            PermissionObject updated,
            AppConfig config
        )
        {
            if (string.IsNullOrWhiteSpace(updated.Name))
                return ApiResult<PermissionObject>.Fail("Permission name is required.");

            try
            {
                // Check if another permission with same name exists
                var conflict = PermissionStore.DoesPermissionNameExist(id, updated.Name);

                if (conflict)
                    return ApiResult<PermissionObject>.Fail("Another permission already uses that name.");

                var permissionObj = PermissionStore.UpdatePermission(id, updated);

                if (permissionObj is null)
                    return ApiResult<PermissionObject>.Fail("Permission update failed or not found.");

                return ApiResult<PermissionObject>.Ok(permissionObj);
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Failed to update permission with ID {Id}", id);
                return ApiResult<PermissionObject>.Fail("Permission update failed.");
            }
        }

        /// <summary>
        /// Retrieves a list of all active permissions from the database.
        /// </summary>
        /// <remarks>The permissions are returned in ascending order by name. Only permissions marked as active 
        /// in the database are included in the result.</remarks>
        /// <returns>An <see cref="ApiResult{T}"/> containing a list of active permission names. The list will be empty if no active
        /// permissions are found.</returns>
        public static ApiResult<List<PermissionObject>> ListAllPermissions()
        {
            try
            {
                var permissions = PermissionStore.ListAllPermissions();

                return ApiResult<List<PermissionObject>>.Ok(permissions);
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Failed to list all permissions");
                return ApiResult<List<PermissionObject>>.Fail("Failed to retrieve permissions");
            }
        }

        /// <summary>
        /// Retrieves a permission object by its unique identifier.
        /// </summary>
        /// <remarks>This method queries the database for a permission with the specified identifier.  If the
        /// permission is found, it is returned as part of a successful <see cref="ApiResult{T}"/>.  Otherwise, a "Not
        /// Found" result is returned.</remarks>
        /// <param name="id">The unique identifier of the permission to retrieve. Cannot be null or empty.</param>
        /// <returns>An <see cref="ApiResult{T}"/> containing the <see cref="PermissionObject"/> if found,  or a "Not Found" result
        /// if no permission with the specified identifier exists.</returns>
        public static ApiResult<PermissionObject> GetPermissionById(string id)
        {
            try
            {
                var permission = PermissionStore.GetPermissionById(id);

                return permission is null
                    ? ApiResult<PermissionObject>.NotFound($"Permission '{id}' not found.")
                    : ApiResult<PermissionObject>.Ok(permission);
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Error retrieving permission by ID {Id}", id);
                return ApiResult<PermissionObject>.Fail("Internal error occurred", 500);
            }
        }

        /// <summary>
        /// Retrieves the unique identifier for a permission based on its name.
        /// </summary>
        /// <remarks>This method interacts with the underlying permission store to retrieve the ID
        /// associated with the specified permission name. Ensure that the provided name is valid and corresponds to an
        /// existing permission.</remarks>
        /// <param name="name">The name of the permission to look up. This parameter cannot be null, empty, or consist solely of
        /// whitespace.</param>
        /// <returns>An <see cref="ApiResult{T}"/> containing the permission ID if found, or an error message and status code if
        /// the lookup fails. If the permission name is invalid, the result will indicate a failure with a 400 status
        /// code. If the permission is not found, the result will indicate a failure with a 404 status code. If an
        /// internal error occurs, the result will indicate a failure with a 500 status code.</returns>
        public static ApiResult<string> GetPermissionIdByName(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
                return ApiResult<string>.Fail("Permission name is required", 400);

            try
            {
                var id = PermissionStore.GetPermissionIdByName(name);

                return id == null
                    ? ApiResult<string>.Fail("Permission not found", 404)
                    : ApiResult<string>.Ok(id);
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Error retrieving permission ID by name");
                return ApiResult<string>.Fail("Internal error occurred", 500);
            }
        }


        /// <summary>
        /// Deletes a permission identified by the specified <paramref name="permissionId"/>.
        /// </summary>
        /// <remarks>This method deletes the specified permission from the database. If the deletion is
        /// successful, an audit log entry is created using the provided <paramref name="config"/> and optional user context
        /// information (<paramref name="userId"/>, <paramref name="ip"/>, and <paramref name="ua"/>). If the deletion
        /// fails, the method returns a failure result.</remarks>
        /// <param name="permissionId">The unique identifier of the permission to delete. Cannot be null or empty.</param>
        /// <param name="config">The application configuration used for logging and auditing. Cannot be null.</param>
        /// <param name="userId">The optional identifier of the user performing the operation, used for auditing purposes.</param>
        /// <param name="ip">The optional IP address of the user performing the operation, used for auditing purposes.</param>
        /// <param name="ua">The optional user agent string of the user performing the operation, used for auditing purposes.</param>
        /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/> that indicates the result of the
        /// operation. Returns a success result if the permission was deleted successfully; otherwise, returns a failure
        /// result with an error message.</returns>
        public static ApiResult<MessageResponse> DeletePermission(
            string permissionId,
            AppConfig config,
            string? userId = null,
            string? ip = null,
            string? ua = null)
        {
            try
            {
                var deleted = PermissionStore.DeletePermission(permissionId);

                if (!deleted)
                    return ApiResult<MessageResponse>.Fail("Failed to delete permission");

                if (config.EnableAuditLogging) 
                    Utils.Audit.Logg("delete_permission", permissionId);

                return ApiResult<MessageResponse>.Ok(new(true, $"Permission '{permissionId}' deleted"));
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Failed to delete permission with ID {PermissionId}", permissionId);
                return ApiResult<MessageResponse>.Fail("Failed to delete permission");
            }
        }

        /// <summary>
        /// Assigns a set of permissions to a specified role.
        /// </summary>
        /// <remarks>This method validates the provided role and permissions before attempting to assign them. If
        /// the role is inactive or does not exist, the method returns a "not found" result. Similarly, any invalid or
        /// inactive permission IDs are ignored during the assignment process.  If at least one permission is successfully
        /// assigned, an audit log entry is created.</remarks>
        /// <param name="roleId">The unique identifier of the role to which permissions will be assigned. Cannot be null, empty, or whitespace.</param>
        /// <param name="permissionIds">A list of unique identifiers for the permissions to assign. Must contain at least one valid permission ID.</param>
        /// <param name="actorUserId">The unique identifier of the user performing the operation. Optional; used for auditing purposes.</param>
        /// <param name="ip">The IP address of the user performing the operation. Optional; used for auditing purposes.</param>
        /// <param name="ua">The user agent string of the user performing the operation. Optional; used for auditing purposes.</param>
        /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/> that indicates the result of the
        /// operation. Returns a success message if permissions were successfully assigned, or an error message if no
        /// permissions were assigned or if the role was not found.</returns>
        public static ApiResult<MessageResponse> AssignPermissionsToRole(
            string roleId,
            string permissionId,
            AppConfig config)
        {
            if (string.IsNullOrWhiteSpace(roleId) || permissionId == null)
                return ApiResult<MessageResponse>.Fail("Role Id and at least one Permission Id are required");

            try
            {
                var assigned = PermissionStore.AssignPermissionToRole(permissionId, roleId);

                if (!assigned)
                    return ApiResult<MessageResponse>.Fail("Failed to assign permission to role or permission already exists");

                if (config.EnableAuditLogging) 
                    Utils.Audit.Logg("assigned_permission", permissionId, roleId);

                return ApiResult<MessageResponse>.Ok(new(true, $"Permission assigned to role {roleId}"));
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Failed to assign permission {PermissionId} to role {RoleId}", permissionId, roleId);
                return ApiResult<MessageResponse>.Fail("Failed to assign permission to role");
            }
        }


        /// <summary>
        /// Removes a permission from a specified role.
        /// </summary>
        /// <remarks>This method performs a database operation to remove the association between a role and a
        /// permission. If the role or permission does not exist, or if the association is already removed, the operation
        /// will fail. Audit logs are created for successful operations, capturing details such as the actor's user ID, IP
        /// address, and user agent.</remarks>
        /// <param name="roleId">The unique identifier of the role from which the permission will be removed. Cannot be null or whitespace.</param>
        /// <param name="permissionId">The unique identifier of the permission to be removed. Cannot be null or whitespace.</param>
        /// <param name="actorUserId">The optional identifier of the user performing the operation. Used for audit logging purposes.</param>
        /// <param name="ip">The optional IP address of the user performing the operation. Used for audit logging purposes.</param>
        /// <param name="ua">The optional user agent string of the user performing the operation. Used for audit logging purposes.</param>
        /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/>. Returns a success result if the
        /// permission is successfully removed from the role. Returns a failure result if the role or permission is not
        /// found, the link does not exist, or the input is invalid.</returns>
        public static ApiResult<MessageResponse> RemovePermissionFromRole(
            string roleId,
            string permissionId,
            AppConfig config)
        {
            if (string.IsNullOrWhiteSpace(roleId) || string.IsNullOrWhiteSpace(permissionId))
                return ApiResult<MessageResponse>.Fail("Role Id and Permission Id are required");

            try
            {
                var removed = PermissionStore.RemovePermissionFromRole(roleId, permissionId);

                if (!removed)
                    return ApiResult<MessageResponse>.Fail("Failed to remove permission from role or permission does not exist");

                if (config.EnableAuditLogging)
                    Utils.Audit.Logg(
                        action: "permission_unassigned",
                        target: roleId,
                        secondary: permissionId
                    );

                return ApiResult<MessageResponse>.Ok(
                    new(true, $"Permission '{permissionId}' removed from role '{roleId}'"));
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Failed to remove permission {PermissionId} from role {RoleId}", permissionId, roleId);
                return ApiResult<MessageResponse>.Fail("Failed to remove permission from role");
            }
        }

        /// <summary>
        /// Retrieves the effective permissions for a specified user.
        /// </summary>
        /// <remarks>This method calculates the effective permissions for a user by aggregating permissions 
        /// assigned through active roles. Only active users, roles, and permissions are considered. The results are ordered
        /// alphabetically by permission name.</remarks>
        /// <param name="userId">The unique identifier of the user for whom to retrieve permissions.  This parameter cannot be null, empty, or
        /// consist only of whitespace.</param>
        /// <returns>An <see cref="ApiResult{T}"/> containing a list of <see cref="PermissionObject"/> objects  that represent the
        /// effective permissions assigned to the user. If the user has no permissions,  the list will be empty. If the
        /// <paramref name="userId"/> is invalid, the result will indicate failure.</returns>
        public static ApiResult<List<PermissionObject>> GetEffectivePermissionsForUser(string userId)
        {
            if (string.IsNullOrWhiteSpace(userId))
                return ApiResult<List<PermissionObject>>.Fail("User Id is required");

            try
            {
                var list = PermissionStore.GetEffectivePermissionsForUser(userId);

                return ApiResult<List<PermissionObject>>.Ok(list);
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Failed to retrieve effective permissions for user {UserId}", userId);
                return ApiResult<List<PermissionObject>>.Fail("Failed to retrieve effective permissions");
            }
        }

        /// <summary>
        /// Determines whether a user has a specific permission based on their roles and active status.
        /// </summary>
        /// <remarks>The method checks the user's roles and permissions in the database, ensuring that both the
        /// user and their associated roles and permissions are active. If the user or permission identifiers are invalid,
        /// the method returns a failure result with an appropriate error message.</remarks>
        /// <param name="userId">The unique identifier of the user. Cannot be null, empty, or whitespace.</param>
        /// <param name="permissionId">The unique identifier of the permission. Cannot be null, empty, or whitespace.</param>
        /// <returns>An <see cref="ApiResult{T}"/> containing an <see cref="AccessCheckResponse"/> that indicates whether the user
        /// has the specified permission. The result will include the user ID, permission ID, and a boolean indicating
        /// access.</returns>
        public static ApiResult<AccessCheckResponse> UserHasPermission(string userId, string permissionId)
        {
            if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(permissionId))
            {
                return ApiResult<AccessCheckResponse>.Fail("User Id and Permission Id are required");
            }

            try
            {
                var hasAccess = PermissionStore.UserHasPermission(userId, permissionId);

                return ApiResult<AccessCheckResponse>.Ok(new AccessCheckResponse(userId, permissionId, hasAccess));
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Error checking permission for user {UserId} and permission {PermissionId}", userId, permissionId);
                return ApiResult<AccessCheckResponse>.Fail("Internal error occurred", 500);
            }
        }

        /// <summary>
        /// Retrieves the list of active permissions associated with a specified role.
        /// </summary>
        /// <remarks>This method queries the database to retrieve permissions associated with the specified role. 
        /// Only active roles and permissions are included in the result. The method returns a failure result  if the role
        /// ID is invalid or if no permissions are found for the specified role.</remarks>
        /// <param name="roleId">The unique identifier of the role. This value cannot be null, empty, or whitespace.</param>
        /// <returns>An <see cref="ApiResult{T}"/> containing a list of <see cref="PermissionObject"/> objects that represent the
        /// active permissions for the specified role. If the <paramref name="roleId"/> is invalid or no permissions are
        /// found, the result will indicate failure with an appropriate error message.</returns>
        public static ApiResult<List<PermissionObject>> GetPermissionsForRole(string roleId)
        {
            if (string.IsNullOrWhiteSpace(roleId))
                return ApiResult<List<PermissionObject>>.Fail("Role Id is required");

            try
            {
                var list = PermissionStore.GetPermissionsForRole(roleId);

                return ApiResult<List<PermissionObject>>.Ok(list);
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Failed to retrieve permissions for role {RoleId}", roleId);
                return ApiResult<List<PermissionObject>>.Fail("Failed to retrieve permissions for role");
            }
        }

        /// <summary>
        /// Retrieves all available permissions as a list of data transfer objects (DTOs).
        /// </summary>
        /// <remarks>This method provides a standardized way to access permission data in the form of
        /// DTOs,  which can be used for further processing or display in client applications.</remarks>
        /// <returns>An <see cref="ApiResult{T}"/> containing a list of <see cref="PermissionDto"/> objects  representing the
        /// available permissions. The result is successful if the operation completes without errors.</returns>
        public static ApiResult<List<PermissionDto>> GetAllPermissionDtos()
        {
            var list = PermissionStore.GetAllPermissionDtos();
            return ApiResult<List<PermissionDto>>.Ok(list);
        }

        /// <summary>
        /// Retrieves a list of permissions assigned to the specified role.
        /// </summary>
        /// <param name="roleId">The unique identifier of the role for which assigned permissions are to be retrieved. Must not be null or
        /// empty.</param>
        /// <returns>An <see cref="ApiResult{T}"/> containing a list of <see cref="PermissionDto"/> objects representing the
        /// permissions assigned to the specified role. If no permissions are assigned, the list will be empty.</returns>
        public static ApiResult<List<PermissionDto>> GetAssignedPermissionDtos(string roleId)
        {
            var list = PermissionStore.GetAssignedPermissionDtos(roleId);
            return ApiResult<List<PermissionDto>>.Ok(list);
        }

        /// <summary>
        /// Replaces the permissions assigned to a specific role with a new set of permissions.
        /// </summary>
        /// <remarks>This method compares the current permissions assigned to the role with the
        /// permissions provided in the <paramref name="dto"/>. It adds any new permissions that are not currently
        /// assigned and removes any permissions that are no longer included. Internal auditing is performed for
        /// permission additions and removals, so no additional logging is required.</remarks>
        /// <param name="dto">An object containing the role identifier and the new set of permissions to assign. The <see
        /// cref="PermissionAssignmentDto.RoleId"/> property must not be null or whitespace.</param>
        /// <param name="config">The application configuration used for permission assignment operations.</param>
        /// <param name="actorUserId">The identifier of the user performing the operation. This is used for auditing purposes.</param>
        /// <param name="ip">The IP address of the user performing the operation. This is optional and may be null.</param>
        /// <param name="ua">The user agent string of the user performing the operation. This is optional and may be null.</param>
        /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/> that indicates whether the
        /// operation was successful. If the operation succeeds, the response contains a success message. If the
        /// <paramref name="dto"/> contains a null or whitespace <see cref="PermissionAssignmentDto.RoleId"/>, the
        /// response indicates failure with a 400 status code.</returns>
        public static ApiResult<MessageResponse> ReplaceRolePermissions(
            PermissionAssignmentDto dto,
            AppConfig config,
            string actorUserId,
            string? ip,
            string? ua)
        {
            if (string.IsNullOrWhiteSpace(dto.RoleId))
                return ApiResult<MessageResponse>.Fail("Missing userId", 400);

            var current = PermissionStore.GetAssignedPermissionDtos(dto.RoleId)
                .Select(r => r.Id)
                .ToHashSet();

            var submitted = dto.Permissions
                .Where(r => !string.IsNullOrWhiteSpace(r.Id))
                .Select(r => r.Id)
                .ToHashSet();

            var toAdd = submitted.Except(current).ToList();
            var toRemove = current.Except(submitted).ToList();

            // AddPermissionToRole and RemovePermissionFromRole are both audit logged internally,
            // so we don't need to log here again as it's redundant.
            foreach (var permId in toAdd)
                AssignPermissionsToRole(dto.RoleId, permId, config, actorUserId, ip, ua);

            foreach (var permId in toRemove)
                RemovePermissionFromRole(dto.RoleId, permId, config, actorUserId, ip, ua);

            return ApiResult<MessageResponse>.Ok(new MessageResponse(true, "Permissions updated."));
        }

        /// <summary>
        /// Retrieves the total number of permissions available in the permission store.
        /// </summary>
        /// <remarks>This method provides a static way to access the number of permissions stored in the
        /// underlying  permission store. It is useful for scenarios where the caller needs to determine the size of 
        /// the permission set.</remarks>
        /// <returns>The total count of permissions as an integer. Returns 0 if no permissions are available.</returns>
        public static int GetPermissionCount() => PermissionStore.GetPermissionCount();
    }
}
