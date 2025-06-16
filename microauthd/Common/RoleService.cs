using madTypes.Api.Requests;
using madTypes.Api.Responses;
using madTypes.Common;
using microauthd.Config;
using Microsoft.Data.Sqlite;
using nebulae.dotArgon2;
using System.Security.Claims;
using System.Text;
using static nebulae.dotArgon2.Argon2;

namespace microauthd.Common;

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
    public static ApiResult<MessageResponse> CreateRole(string name, string? description, AppConfig config, string? userId = null, string? ip = null, string? ua = null)
    {
        if (string.IsNullOrWhiteSpace(name))
            return ApiResult<MessageResponse>.Fail("Role name is required");

        var success = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                INSERT INTO roles (id, name, description, created_at, modified_at, is_active)
                VALUES ($id, $name, $desc, datetime('now'), datetime('now'), 1);
            """;
            cmd.Parameters.AddWithValue("$id", Guid.NewGuid().ToString());
            cmd.Parameters.AddWithValue("$name", name);
            cmd.Parameters.AddWithValue("$desc", description ?? "");

            try
            {
                return cmd.ExecuteNonQuery() == 1;
            }
            catch (SqliteException)
            {
                return false; // likely duplicate
            }
        });

        if (!success)
            return ApiResult<MessageResponse>.Fail("Role creation failed (maybe duplicate?)");

        AuditLogger.AuditLog(
            config: config,
            userId: userId,
            action: "role_created",
            target: name,
            ipAddress: ip,
            userAgent: ua
        );

        return ApiResult<MessageResponse>.Ok(new($"Created role '{name}'"));
    }


    /// <summary>
    /// Retrieves a list of all active role names from the database.
    /// </summary>
    /// <remarks>The roles are returned in ascending order by name. Only roles marked as active in the
    /// database are included in the result.</remarks>
    /// <returns>An <see cref="ApiResult{T}"/> containing a list of active role names. The list will be empty if no active roles
    /// are found.</returns>
    public static ApiResult<List<RoleResponse>> ListAllRoles()
    {
        var roles = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT id, name, description, is_protected
                FROM roles
                WHERE is_active = 1
                ORDER BY name ASC;
            """;

            using var reader = cmd.ExecuteReader();
            var list = new List<RoleResponse>();
            while (reader.Read())
            {
                list.Add(new RoleResponse
                {
                    Id = reader.GetString(0),
                    Name = reader.GetString(1),
                    Description = reader.IsDBNull(2) ? null : reader.GetString(2),
                    IsProtected = reader.GetInt32(3) == 1
                });
            }

            return list;
        });

        return ApiResult<List<RoleResponse>>.Ok(roles);
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

        return Db.WithConnection(conn =>
        {
            // Look up user
            string? lookedUpUserId;
            using (var cmd = conn.CreateCommand())
            {
                cmd.CommandText = "SELECT id FROM users WHERE id = $uid;";
                cmd.Parameters.AddWithValue("$uid", userId.ToLowerInvariant());
                lookedUpUserId = cmd.ExecuteScalar() as string;
            }

            // Look up role
            string? lookedUpRoleId;
            using (var cmd = conn.CreateCommand())
            {
                cmd.CommandText = "SELECT id FROM roles WHERE id = $rid;";
                cmd.Parameters.AddWithValue("$rid", roleId.ToLowerInvariant());
                lookedUpRoleId = cmd.ExecuteScalar() as string;
            }

            if (lookedUpUserId is null || lookedUpRoleId is null)
                return ApiResult<MessageResponse>.Fail("User or role not found.");

            // Insert role assignment
            using var cmd2 = conn.CreateCommand();
            cmd2.CommandText = """
                INSERT INTO user_roles (id, user_id, role_id, assigned_at)
                VALUES ($id, $uid, $rid, datetime('now'));
            """;
            cmd2.Parameters.AddWithValue("$id", Guid.NewGuid().ToString());
            cmd2.Parameters.AddWithValue("$uid", lookedUpUserId);
            cmd2.Parameters.AddWithValue("$rid", lookedUpRoleId);
            cmd2.ExecuteNonQuery();

            AuditLogger.AuditLog(
                config: config,
                userId: actorId,
                action: "role_assigned",
                target: $"user:{userId} -> role:{roleId}",
                ipAddress: ip,
                userAgent: ua
            );

            return ApiResult<MessageResponse>.Ok(new($"Assigned role '{roleId}' to user '{userId}'"));
        });
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

        var roles = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT r.name FROM user_roles ur
                JOIN roles r ON ur.role_id = r.id
                JOIN users u ON ur.user_id = u.id
                WHERE u.id = $uid
                  AND ur.is_active = 1
                  AND r.is_active = 1
                ORDER BY r.name ASC;
            """;
            cmd.Parameters.AddWithValue("$uid", userId);

            using var reader = cmd.ExecuteReader();
            var list = new List<string>();
            while (reader.Read())
                list.Add(reader.GetString(0));

            return list;
        });

        return ApiResult<List<string>>.Ok(roles);
    }


    /// <summary>
    /// Marks a role as inactive (soft delete) in the system.
    /// </summary>
    /// <remarks>This method performs a soft delete by setting the role's "is_active" status to 0 in the
    /// database.  It also logs the operation in the audit log if a <paramref name="userId"/> is provided.</remarks>
    /// <param name="roleId">The unique identifier of the role to be marked as inactive. Cannot be null, empty, or whitespace.</param>
    /// <param name="userId">The identifier of the user performing the operation. Optional.</param>
    /// <param name="ip">The IP address of the user performing the operation. Optional.</param>
    /// <param name="ua">The user agent string of the user performing the operation. Optional.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/>.  Returns a success result if the role
    /// was successfully marked as inactive.  Returns a failure result if the role does not exist, is already inactive,
    /// or if the <paramref name="roleId"/> is invalid.</returns>
    public static ApiResult<MessageResponse> SoftDeleteRole(
        string roleId,
        AppConfig config,
        string? userId = null,
        string? ip = null,
        string? ua = null)
    {
        if (string.IsNullOrWhiteSpace(roleId))
            return ApiResult<MessageResponse>.Fail("Role Id is required");

        var isProtected = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT is_protected FROM roles WHERE id = $rid;";
            cmd.Parameters.AddWithValue("$rid", roleId);
            return Convert.ToInt32(cmd.ExecuteScalar() ?? 0) == 1;
        });

        if (isProtected)
            return ApiResult<MessageResponse>.Fail("Cannot delete protected role.", 400);

        var deleted = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                UPDATE roles
                SET is_active = 0
                WHERE id = $rid AND is_active = 1;
            """;
            cmd.Parameters.AddWithValue("$rid", roleId);
            return cmd.ExecuteNonQuery() > 0;
        });

        if (!deleted)
            return ApiResult<MessageResponse>.Fail("Role not found or already deleted");

        AuditLogger.AuditLog(
            config: config,
            userId: userId,
            action: "role_deleted",
            target: roleId,
            ipAddress: ip,
            userAgent: ua
        );

        return ApiResult<MessageResponse>.Ok(new($"Role '{roleId}' marked as inactive"));
    }


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
    public static ApiResult<MessageResponse> CreatePermission(string name, AppConfig config, string? userId, string? ip = null, string? ua = null)
    {
        if (string.IsNullOrWhiteSpace(name))
            return ApiResult<MessageResponse>.Fail("Permission name is required");

        var success = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                INSERT INTO permissions (id, name, created_at, is_active)
                VALUES ($id, $name, datetime('now'), 1);
            """;
            cmd.Parameters.AddWithValue("$id", Guid.NewGuid().ToString());
            cmd.Parameters.AddWithValue("$name", name);
            try
            {
                return cmd.ExecuteNonQuery() == 1;
            }
            catch (SqliteException)
            {
                return false; // likely duplicate
            }
        });

        if (!success)
            return ApiResult<MessageResponse>.Fail("Permission creation failed (maybe duplicate?)");

        AuditLogger.AuditLog(config, userId, "create_permission", name, ip, ua);
        return ApiResult<MessageResponse>.Ok(new($"Permission '{name}' created"));
    }


    /// <summary>
    /// Retrieves a list of all active permissions from the database.
    /// </summary>
    /// <remarks>The permissions are returned in ascending order by name. Only permissions marked as active 
    /// in the database are included in the result.</remarks>
    /// <returns>An <see cref="ApiResult{T}"/> containing a list of active permission names. The list will be empty if no active
    /// permissions are found.</returns>
    public static ApiResult<List<PermissionResponse>> ListAllPermissions()
    {
        var permissions = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT id, name FROM permissions
                WHERE is_active = 1
                ORDER BY name ASC;
            """;

            using var reader = cmd.ExecuteReader();
            var list = new List<PermissionResponse>();
            while (reader.Read())
            {
                list.Add(new PermissionResponse
                {
                    Id = reader.GetString(0),
                    Name = reader.GetString(1)
                });
            }

            return list;
        });

        return ApiResult<List<PermissionResponse>>.Ok(permissions);
    }

    /// <summary>
    /// Marks a permission as inactive (soft deletes it) by updating its status in the database.
    /// </summary>
    /// <remarks>This method performs a soft delete by setting the <c>is_active</c> flag of the specified
    /// permission to 0. If the operation is successful, an audit log entry is created to record the action.</remarks>
    /// <param name="permissionId">The unique identifier of the permission to be soft deleted. Cannot be null or whitespace.</param>
    /// <param name="actorUserId">The identifier of the user performing the operation. Optional.</param>
    /// <param name="ip">The IP address of the user performing the operation. Optional.</param>
    /// <param name="ua">The user agent string of the user performing the operation. Optional.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/>.  Returns a success result if the
    /// permission was successfully marked as inactive.  Returns a "not found" result if the permission does not exist
    /// or is already inactive.  Returns a failure result if the <paramref name="permissionId"/> is invalid.</returns>
    public static ApiResult<MessageResponse> SoftDeletePermission(string permissionId, AppConfig config, string? actorUserId = null, string? ip = null, string? ua = null)
    {
        if (string.IsNullOrWhiteSpace(permissionId))
            return ApiResult<MessageResponse>.Fail("Permission Id is required");

        var affected = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                UPDATE permissions
                SET is_active = 0
                WHERE id = $pid AND is_active = 1;
            """;
            cmd.Parameters.AddWithValue("$pid", permissionId);
            return cmd.ExecuteNonQuery();
        });

        if (affected > 0)
        {
            AuditLogger.AuditLog(config, actorUserId, "permission_deleted", permissionId, ip, ua);
            return ApiResult<MessageResponse>.Ok(new($"Permission '{permissionId}' marked as inactive"));
        }

        return ApiResult<MessageResponse>.NotFound("Permission not found or already deleted");
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
        List<string> permissionIds,
        AppConfig config, 
        string? actorUserId = null,
        string? ip = null,
        string? ua = null)
    {
        if (string.IsNullOrWhiteSpace(roleId) || permissionIds.Count == 0)
            return ApiResult<MessageResponse>.Fail("Role Id and at least one Permission Id are required");

        return Db.WithConnection(conn =>
        {
            string? lookedUpRoleId = null;
            using (var cmd = conn.CreateCommand())
            {
                cmd.CommandText = "SELECT id FROM roles WHERE id = $rid AND is_active = 1;";
                cmd.Parameters.AddWithValue("$rid", roleId);
                lookedUpRoleId = cmd.ExecuteScalar() as string;
            }

            if (lookedUpRoleId is null)
                return ApiResult<MessageResponse>.NotFound("Role not found or inactive");

            int assigned = 0;

            foreach (var permId in permissionIds)
            {
                string? lookedUpPermId = null;
                using (var cmd = conn.CreateCommand())
                {
                    cmd.CommandText = "SELECT id FROM permissions WHERE id = $pid AND is_active = 1;";
                    cmd.Parameters.AddWithValue("$pid", permId);
                    lookedUpPermId = cmd.ExecuteScalar() as string;
                }

                if (lookedUpPermId is null)
                    continue;

                using var cmdInsert = conn.CreateCommand();
                cmdInsert.CommandText = """
                    INSERT OR IGNORE INTO role_permissions (id, role_id, permission_id)
                    VALUES ($id, $roleId, $permId);
                """;
                cmdInsert.Parameters.AddWithValue("$id", Guid.NewGuid().ToString());
                cmdInsert.Parameters.AddWithValue("$roleId", lookedUpRoleId);
                cmdInsert.Parameters.AddWithValue("$permId", lookedUpPermId);

                assigned += cmdInsert.ExecuteNonQuery();
            }

            if (assigned > 0)
            {
                AuditLogger.AuditLog(config, actorUserId, "assigned_permissions", roleId, ip, ua);
                return ApiResult<MessageResponse>.Ok(new($"Permissions assigned to role '{roleId}'"));
            }

            return ApiResult<MessageResponse>.Fail("No permissions were assigned — check if permission IDs are valid");
        });
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
        AppConfig config,
        string? actorUserId = null,
        string? ip = null,
        string? ua = null)
    {
        if (string.IsNullOrWhiteSpace(roleId) || string.IsNullOrWhiteSpace(permissionId))
            return ApiResult<MessageResponse>.Fail("Role Id and Permission Id are required");

        return Db.WithConnection(conn =>
        {
            string? lookedUpRoleId;
            using (var cmd = conn.CreateCommand())
            {
                cmd.CommandText = "SELECT id FROM roles WHERE id = $rid AND is_active = 1;";
                cmd.Parameters.AddWithValue("$rid", roleId);
                lookedUpRoleId = cmd.ExecuteScalar() as string;
            }

            string? lookedUpPermId;
            using (var cmd = conn.CreateCommand())
            {
                cmd.CommandText = "SELECT id FROM permissions WHERE id = $pid AND is_active = 1;";
                cmd.Parameters.AddWithValue("$pid", permissionId);
                lookedUpPermId = cmd.ExecuteScalar() as string;
            }

            if (lookedUpRoleId is null || lookedUpPermId is null)
                return ApiResult<MessageResponse>.Fail("Role or permission not found");

            using var cmdDel = conn.CreateCommand();
            cmdDel.CommandText = """
                DELETE FROM role_permissions
                WHERE role_id = $rid AND permission_id = $pid;
            """;
            cmdDel.Parameters.AddWithValue("$rid", lookedUpRoleId);
            cmdDel.Parameters.AddWithValue("$pid", lookedUpPermId);

            var removed = cmdDel.ExecuteNonQuery();
            if (removed == 0)
                return ApiResult<MessageResponse>.Fail("Link not found or already removed");

            AuditLogger.AuditLog(
                config: config,
                userId: actorUserId,
                action: "permission_unassigned",
                target: $"role:{roleId} -> permission:{permissionId}",
                ipAddress: ip,
                userAgent: ua
            );

            return ApiResult<MessageResponse>.Ok(
                new($"Permission '{permissionId}' removed from role '{roleId}'"));
        });
    }


    /// <summary>
    /// Retrieves the effective permissions for a specified user.
    /// </summary>
    /// <remarks>The method queries the database to determine the permissions assigned to the user through
    /// their roles.  Only active users, roles, and permissions are considered. The permissions are returned in
    /// ascending order.</remarks>
    /// <param name="userId">The unique identifier of the user whose permissions are to be retrieved. Cannot be null, empty, or whitespace.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a list of permission names assigned to the user.  If the user has no
    /// permissions, the list will be empty. If the <paramref name="userId"/> is invalid, the result will indicate
    /// failure.</returns>
    public static ApiResult<List<string>> GetEffectivePermissionsForUser(string userId)
    {
        if (string.IsNullOrWhiteSpace(userId))
            return ApiResult<List<string>>.Fail("User Id is required");

        var list = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT DISTINCT p.name
                FROM users u
                JOIN user_roles ur ON u.id = ur.user_id
                JOIN roles r ON ur.role_id = r.id
                JOIN role_permissions rp ON r.id = rp.role_id
                JOIN permissions p ON rp.permission_id = p.id
                WHERE u.id = $uid
                  AND u.is_active = 1
                  AND ur.is_active = 1
                  AND r.is_active = 1
                  AND p.is_active = 1
                ORDER BY p.name ASC;
            """;
            cmd.Parameters.AddWithValue("$uid", userId);

            using var reader = cmd.ExecuteReader();
            var perms = new List<string>();
            while (reader.Read())
                perms.Add(reader.GetString(0));

            return perms;
        });

        return ApiResult<List<string>>.Ok(list);
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

        var hasAccess = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT 1
                FROM users u
                JOIN user_roles ur ON u.id = ur.user_id
                JOIN roles r ON ur.role_id = r.id
                JOIN role_permissions rp ON r.id = rp.role_id
                JOIN permissions p ON rp.permission_id = p.id
                WHERE u.id = $uid
                  AND p.id = $pid
                  AND u.is_active = 1
                  AND ur.is_active = 1
                  AND r.is_active = 1
                  AND p.is_active = 1
                LIMIT 1;
            """;
            cmd.Parameters.AddWithValue("$uid", userId);
            cmd.Parameters.AddWithValue("$pid", permissionId);

            using var reader = cmd.ExecuteReader();
            return reader.Read();
        });

        return ApiResult<AccessCheckResponse>.Ok(new AccessCheckResponse(userId, permissionId, hasAccess));
    }

    /// <summary>
    /// Retrieves the list of active permissions associated with a specified role.
    /// </summary>
    /// <remarks>This method queries the database to retrieve permissions for the specified role.  Both the
    /// role and its associated permissions must be active to be included in the result.</remarks>
    /// <param name="roleId">The unique identifier of the role. This value cannot be null, empty, or whitespace.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a list of permission names associated with the role. If the role does
    /// not exist, is inactive, or has no active permissions, the list will be empty. Returns a failure result if
    /// <paramref name="roleId"/> is null, empty, or whitespace.</returns>
    public static ApiResult<List<string>> GetPermissionsForRole(string roleId)
    {
        if (string.IsNullOrWhiteSpace(roleId))
            return ApiResult<List<string>>.Fail("Role Id is required");

        var list = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT p.name
                FROM role_permissions rp
                JOIN roles r ON rp.role_id = r.id
                JOIN permissions p ON rp.permission_id = p.id
                WHERE r.id = $rid AND r.is_active = 1 AND p.is_active = 1;
            """;
            cmd.Parameters.AddWithValue("$rid", roleId);

            using var reader = cmd.ExecuteReader();
            var results = new List<string>();
            while (reader.Read())
                results.Add(reader.GetString(0));

            return results;
        });

        return ApiResult<List<string>>.Ok(list);
    }


    /// <summary>
    /// Retrieves a list of role claims for the specified user.
    /// </summary>
    /// <remarks>This method queries the database to retrieve all active roles associated with the specified
    /// user.  Each role is returned as a claim of type <see cref="ClaimTypes.Role"/>.</remarks>
    /// <param name="userId">The unique identifier of the user whose role claims are to be retrieved. Cannot be null or empty.</param>
    /// <returns>A list of <see cref="Claim"/> objects representing the roles assigned to the user.  The list will be empty if
    /// the user has no active roles.</returns>
    public static List<Claim> GetRoleClaimsForUser(string userId)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT r.id FROM user_roles ur
                JOIN roles r ON ur.role_id = r.id
                WHERE ur.user_id = $uid
                  AND ur.is_active = 1
                  AND r.is_active = 1;
            """;
            cmd.Parameters.AddWithValue("$uid", userId);

            using var reader = cmd.ExecuteReader();
            var claims = new List<Claim>();

            while (reader.Read())
            {
                var roleId = reader.GetString(0);
                claims.Add(new Claim(ClaimTypes.Role, roleId));
            }

            return claims;
        });
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

        return Db.WithConnection(conn =>
        {
            string? lookedUpUserId;
            using (var cmd = conn.CreateCommand())
            {
                cmd.CommandText = "SELECT id FROM users WHERE id = $uid;";
                cmd.Parameters.AddWithValue("$uid", userId);
                lookedUpUserId = cmd.ExecuteScalar() as string;
            }

            string? lookedUpRoleId;
            using (var cmd = conn.CreateCommand())
            {
                cmd.CommandText = "SELECT id FROM roles WHERE id = $rid;";
                cmd.Parameters.AddWithValue("$rid", roleId);
                lookedUpRoleId = cmd.ExecuteScalar() as string;
            }

            if (lookedUpUserId is null || lookedUpRoleId is null)
                return ApiResult<MessageResponse>.Fail("User or role not found");

            using var deleteCmd = conn.CreateCommand();
            deleteCmd.CommandText = """
                DELETE FROM user_roles
                WHERE user_id = $uid AND role_id = $rid;
            """;
            deleteCmd.Parameters.AddWithValue("$uid", userId);
            deleteCmd.Parameters.AddWithValue("$rid", roleId);
            var removed = deleteCmd.ExecuteNonQuery();

            if (removed == 0)
                return ApiResult<MessageResponse>.Fail("Role was not assigned or already removed");

            AuditLogger.AuditLog(
                config: config,
                userId: actorId,
                action: "role_unassigned",
                target: $"user:{userId} -> role:{roleId}",
                ipAddress: ip,
                userAgent: ua
            );

            return ApiResult<MessageResponse>.Ok(
                new($"Removed role '{roleId}' from user '{userId}'"));
        });
    }


    /// <summary>
    /// Creates a new scope with the specified name and description.
    /// </summary>
    /// <remarks>This method validates the scope name before attempting to create the scope. If the name is
    /// invalid, the operation fails immediately. If a scope with the same name already exists, the operation fails and
    /// returns an appropriate error message. The method also logs the operation for auditing purposes if the optional
    /// auditing parameters are provided.</remarks>
    /// <param name="req">The request containing the name and description of the scope to create. The <see cref="ScopeResponse.Name"/>
    /// must be non-empty, alphanumeric, and may include hyphens or underscores.</param>
    /// <param name="actorUserId">The optional ID of the user performing the operation, used for auditing purposes.</param>
    /// <param name="ip">The optional IP address of the user performing the operation, used for auditing purposes.</param>
    /// <param name="ua">The optional user agent string of the user performing the operation, used for auditing purposes.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/>.  If the operation succeeds, the result
    /// indicates success and includes a message confirming the creation of the scope.  If the operation fails, the
    /// result indicates failure and includes an error message.</returns>
    public static ApiResult<MessageResponse> CreateScope(
    ScopeResponse req,
    AppConfig config,
    string? actorUserId = null,
    string? ip = null,
    string? ua = null)
    {
        if (!Utils.IsValidTokenName(req.Name))
            return ApiResult<MessageResponse>.Fail("Invalid scope name: must be non-empty, alphanumeric, -, or _");

        var created = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                INSERT INTO scopes (id, name, description, created_at, is_active)
                VALUES ($id, $name, $desc, datetime('now'), 1);
            """;
            cmd.Parameters.AddWithValue("$id", Guid.NewGuid().ToString());
            cmd.Parameters.AddWithValue("$name", req.Name);
            cmd.Parameters.AddWithValue("$desc", req.Description ?? "");

            try
            {
                cmd.ExecuteNonQuery();
                return true;
            }
            catch
            {
                return false; // likely duplicate
            }
        });

        if (!created)
            return ApiResult<MessageResponse>.Fail("Scope creation failed (duplicate name?)");

        AuditLogger.AuditLog(config, actorUserId, "create_scope", req.Name, ip, ua);

        return ApiResult<MessageResponse>.Ok(new($"Created scope '{req.Name}'"));
    }

    /// <summary>
    /// Deactivates a scope by marking it as inactive in the database.
    /// </summary>
    /// <param name="scopeId">The unique identifier of the scope to deactivate. Cannot be null, empty, or whitespace.</param>
    /// <param name="actorUserId">The optional identifier of the user performing the operation. Used for audit logging.</param>
    /// <param name="ip">The optional IP address of the user performing the operation. Used for audit logging.</param>
    /// <param name="ua">The optional user agent string of the user performing the operation. Used for audit logging.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/>.  Returns a success result if the scope
    /// was successfully deactivated, or a failure result if the scope was not found or is already inactive.</returns>
    public static ApiResult<MessageResponse> SoftDeleteScope(
        string scopeId,
        AppConfig config,
        string? actorUserId = null,
        string? ip = null,
        string? ua = null)
    {
        if (string.IsNullOrWhiteSpace(scopeId))
            return ApiResult<MessageResponse>.Fail("Scope ID is required");

        var isProtected = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT is_protected FROM scopes WHERE id = $sid;";
            cmd.Parameters.AddWithValue("$sid", scopeId);
            return Convert.ToInt32(cmd.ExecuteScalar() ?? 0) == 1;
        });

        if (isProtected)
            return ApiResult<MessageResponse>.Fail("Cannot delete protected scope.", 400);

        var affected = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "UPDATE scopes SET is_active = 0 WHERE id = $sid AND is_active = 1;";
            cmd.Parameters.AddWithValue("$sid", scopeId);
            return cmd.ExecuteNonQuery();
        });

        if (affected == 0)
            return ApiResult<MessageResponse>.Fail("Scope not found or already inactive");

        AuditLogger.AuditLog(config, actorUserId, "delete_scope", scopeId, ip, ua);

        return ApiResult<MessageResponse>.Ok(new($"Scope '{scopeId}' deactivated."));
    }


    /// <summary>
    /// Attempts to create a new client with the specified request parameters and configuration.
    /// </summary>
    /// <remarks>The method validates the provided client ID and client secret before attempting to create the
    /// client.  If the client creation fails (e.g., due to a duplicate client ID), an error message is
    /// returned.</remarks>
    /// <param name="req">The request containing the client details, including <see cref="CreateClientRequest.ClientId"/> and <see
    /// cref="CreateClientRequest.ClientSecret"/>.</param>
    /// <param name="config">The application configuration used for hashing and other settings.</param>
    /// <param name="actorUserId">The optional ID of the user performing the operation, used for auditing purposes.</param>
    /// <param name="ip">The optional IP address of the user performing the operation, used for auditing purposes.</param>
    /// <param name="ua">The optional user agent string of the user performing the operation, used for auditing purposes.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/>.  If the client is successfully
    /// created, the result is successful and includes a message indicating the created client ID.  Otherwise, the
    /// result is a failure with an appropriate error message.</returns>
    public static ApiResult<MessageResponse> TryCreateClient(
        CreateClientRequest req,
        AppConfig config,
        string? actorUserId = null,
        string? ip = null,
        string? ua = null)
    {
        if (!Utils.IsValidTokenName(req.ClientId))
            return ApiResult<MessageResponse>.Fail("Invalid client_id");

        if (string.IsNullOrWhiteSpace(req.ClientSecret))
            return ApiResult<MessageResponse>.Fail("Client secret required");

        var hash = Argon2.Argon2HashEncodedToString(
            Argon2Algorithm.Argon2id,
            (uint)config.Argon2Time,
            (uint)config.Argon2Memory,
            (uint)config.Argon2Parallelism,
            Encoding.UTF8.GetBytes(req.ClientSecret),
            Utils.GenerateSalt(config.Argon2SaltLength),
            config.Argon2HashLength
        );

        var clientId = Guid.NewGuid().ToString();

        try
        {
            Db.WithConnection(conn =>
            {
                using var cmd = conn.CreateCommand();
                cmd.CommandText = """
                    INSERT INTO clients (id, client_id, client_secret_hash, display_name, created_at, is_active)
                    VALUES ($id, $cid, $hash, $name, datetime('now'), 1);
                """;
                cmd.Parameters.AddWithValue("$id", clientId);
                cmd.Parameters.AddWithValue("$cid", req.ClientId);
                cmd.Parameters.AddWithValue("$hash", hash);
                cmd.Parameters.AddWithValue("$name", req.DisplayName ?? "");
                cmd.ExecuteNonQuery();
            });

            AuditLogger.AuditLog(config, actorUserId, "create_client", req.ClientId, ip, ua);

            return ApiResult<MessageResponse>.Ok(
                new MessageResponse($"Created client '{req.ClientId}'"));
        }
        catch
        {
            return ApiResult<MessageResponse>.Fail("Client creation failed (duplicate client_id?)");
        }
    }


    /// <summary>
    /// Retrieves a list of all active clients from the database.
    /// </summary>
    /// <remarks>This method queries the database for clients that are marked as active and returns them in
    /// ascending order of their client IDs. Each client is represented as a <see cref="ClientResponse"/>
    /// object.</remarks>
    /// <returns>An <see cref="ApiResult{T}"/> containing a list of <see cref="ClientResponse"/> objects representing the active
    /// clients. If no active clients are found, the list will be empty.</returns>
    public static ApiResult<List<ClientResponse>> GetAllClients()
    {
        var clients = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT id, client_id, display_name, created_at, is_active
                FROM clients
                WHERE is_active = 1
                ORDER BY client_id ASC;
            """;

            using var reader = cmd.ExecuteReader();
            var list = new List<ClientResponse>();

            while (reader.Read())
            {
                list.Add(new ClientResponse
                {
                    Id = reader.GetString(0),
                    ClientId = reader.GetString(1),
                    DisplayName = reader.IsDBNull(2) ? string.Empty : reader.GetString(2),
                    CreatedAt = reader.GetString(3),
                    IsActive = reader.GetInt64(4) == 1
                });
            }

            return list;
        });

        return ApiResult<List<ClientResponse>>.Ok(clients);
    }

    /// <summary>
    /// Deactivates a client by marking it as inactive in the database.
    /// </summary>
    /// <remarks>This method updates the client's status in the database to mark it as inactive.  If the
    /// client does not exist or is already inactive, the operation will fail. Audit logging is performed if <paramref
    /// name="actorUserId"/> is provided.</remarks>
    /// <param name="clientId">The unique identifier of the client to deactivate. Cannot be null, empty, or whitespace.</param>
    /// <param name="actorUserId">The optional identifier of the user performing the operation. Used for audit logging.</param>
    /// <param name="ip">The optional IP address of the user performing the operation. Used for audit logging.</param>
    /// <param name="ua">The optional user agent string of the user performing the operation. Used for audit logging.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/>.  Returns a success result if the
    /// client was successfully deactivated, or a failure result if the client was not found or is already inactive.</returns>
    public static ApiResult<MessageResponse> SoftDeleteClient(
        string clientId,
        AppConfig config,
        string? actorUserId = null,
        string? ip = null,
        string? ua = null)
    {
        if (string.IsNullOrWhiteSpace(clientId))
            return ApiResult<MessageResponse>.Fail("Client ID is required");

        var affected = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "UPDATE clients SET is_active = 0 WHERE id = $id AND is_active = 1;";
            cmd.Parameters.AddWithValue("$id", clientId);
            return cmd.ExecuteNonQuery();
        });

        if (affected == 0)
            return ApiResult<MessageResponse>.Fail("Client not found or already inactive");

        AuditLogger.AuditLog(config,actorUserId, "delete_client", clientId, ip, ua);

        return ApiResult<MessageResponse>.Ok(new($"Client '{clientId}' deactivated."));
    }


    /// <summary>
    /// Retrieves a list of all active scopes from the database.
    /// </summary>
    /// <remarks>This method queries the database for all scopes that are marked as active and returns them in
    /// ascending order by name. Each scope includes its ID, name, description, creation date, and active
    /// status.</remarks>
    /// <returns>An <see cref="ApiResult{T}"/> containing a list of <see cref="ScopeResponse"/> objects representing the active
    /// scopes. If no active scopes are found, the list will be empty.</returns>
    public static ApiResult<List<ScopeResponse>> ListAllScopes()
    {
        var scopes = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT id, name, description, created_at, is_active
                FROM scopes
                WHERE is_active = 1
                ORDER BY name ASC;
            """;

            using var reader = cmd.ExecuteReader();
            var list = new List<ScopeResponse>();

            while (reader.Read())
            {
                list.Add(new ScopeResponse
                {
                    Id = reader.GetString(0),
                    Name = reader.GetString(1),
                    Description = reader.IsDBNull(2) ? null : reader.GetString(2),
                    CreatedAt = reader.GetString(3),
                    IsActive = reader.GetInt64(4) == 1
                });
            }

            return list;
        });

        return ApiResult<List<ScopeResponse>>.Ok(scopes);
    }


    /// <summary>
    /// Assigns one or more scopes to a client, ensuring that the scopes are active and valid.
    /// </summary>
    /// <remarks>This method ensures that only active and valid scopes are assigned to the client. Duplicate
    /// or invalid scope IDs are ignored. If no valid scopes are assigned, the method returns a failure result.  The
    /// operation is logged for auditing purposes if <paramref name="actorUserId"/>, <paramref name="ip"/>, or <paramref
    /// name="ua"/> is provided.</remarks>
    /// <param name="clientId">The unique identifier of the client to which the scopes will be assigned. Cannot be null, empty, or whitespace.</param>
    /// <param name="req">The request containing the list of scope IDs to assign. Must include at least one valid scope ID.</param>
    /// <param name="actorUserId">The optional identifier of the user performing the operation, used for auditing purposes.</param>
    /// <param name="ip">The optional IP address of the user performing the operation, used for auditing purposes.</param>
    /// <param name="ua">The optional user agent string of the user performing the operation, used for auditing purposes.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/> that indicates the result of the
    /// operation. Returns a success result if at least one scope was successfully assigned to the client. Returns a
    /// failure result if no scopes were assigned or if the input parameters are invalid.</returns>
    public static ApiResult<MessageResponse> AddScopesToClient(
        string clientId,
        AssignScopesRequest req,
        AppConfig config,
        string? actorUserId = null,
        string? ip = null,
        string? ua = null)
    {
        if (string.IsNullOrWhiteSpace(clientId))
            return ApiResult<MessageResponse>.Fail("Client ID is required");

        if (req.ScopeIds is null || req.ScopeIds.Count == 0)
            return ApiResult<MessageResponse>.Fail("At least one scope ID is required");

        int added = Db.WithConnection(conn =>
        {
            int count = 0;

            foreach (var scopeId in req.ScopeIds.Distinct())
            {
                string? lookedUpScopeId = null;

                using (var getCmd = conn.CreateCommand())
                {
                    getCmd.CommandText = "SELECT id FROM scopes WHERE id = $sid AND is_active = 1;";
                    getCmd.Parameters.AddWithValue("$sid", scopeId);
                    lookedUpScopeId = getCmd.ExecuteScalar() as string;
                }

                if (lookedUpScopeId is null)
                    continue;

                using var cmd = conn.CreateCommand();
                cmd.CommandText = """
                    INSERT OR IGNORE INTO client_scopes (id, client_id, scope_id, assigned_at, is_active)
                    VALUES ($id, $cid, $sid, datetime('now'), 1);
                """;
                cmd.Parameters.AddWithValue("$id", Guid.NewGuid().ToString());
                cmd.Parameters.AddWithValue("$cid", clientId);
                cmd.Parameters.AddWithValue("$sid", lookedUpScopeId);
                count += cmd.ExecuteNonQuery();
            }

            return count;
        });

        if (added == 0)
            return ApiResult<MessageResponse>.Fail("No scopes were assigned. Check scope IDs or duplicates.");

        AuditLogger.AuditLog(config, actorUserId, "assign_scope_to_client", clientId, ip, ua);

        return ApiResult<MessageResponse>.Ok(new($"Assigned {added} scope(s) to client."));
    }


    /// <summary>
    /// Retrieves the list of active scopes associated with a specified client.
    /// </summary>
    /// <remarks>This method queries the database to retrieve the active scopes linked to the
    /// specified client.  Only scopes, clients, and client-scope relationships marked as active are included in the
    /// result.</remarks>
    /// <param name="clientId">The unique identifier of the client for which to retrieve the associated scopes.  This value cannot be null
    /// or empty.</param>
    /// <returns>A list of strings representing the names of the active scopes associated with the specified client.  The
    /// list will be empty if no active scopes are found.</returns>
    public static List<string> ListScopesForClient(string clientId)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                    SELECT s.name
                        FROM user_scopes us
                        JOIN scopes s ON us.scope_id = s.id
                        WHERE us.user_id = $uid
                          AND us.is_active = 1
                          AND s.is_active = 1
                          AND s.name IS NOT NULL;
                """;
            cmd.Parameters.AddWithValue("$cid", clientId);

            using var reader = cmd.ExecuteReader();
            var scopes = new List<string>();
            while (reader.Read())
                scopes.Add(reader.GetString(0));

            return scopes;
        });
    }

    /// <summary>
    /// Retrieves the list of active scopes associated with a specified client.
    /// </summary>
    /// <remarks>This method queries the database to retrieve scopes that are both active and associated with
    /// the specified client. The returned scopes include details such as the scope's ID, name, description, creation
    /// date, and active status.</remarks>
    /// <param name="clientId">The unique identifier of the client for which to retrieve scopes. Cannot be null, empty, or whitespace.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a list of <see cref="ScopeResponse"/> objects representing the active
    /// scopes for the client. If the <paramref name="clientId"/> is invalid, the result will indicate failure with an
    /// appropriate error message.</returns>
    public static ApiResult<List<ScopeResponse>> GetScopesForClient(string clientId)
    {
        if (string.IsNullOrWhiteSpace(clientId))
            return ApiResult<List<ScopeResponse>>.Fail("Client ID is required");

        var scopes = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT s.id, s.name, s.description, s.created_at, s.is_active
                FROM client_scopes cs
                JOIN scopes s ON cs.scope_id = s.id
                WHERE cs.client_id = $id AND cs.is_active = 1 AND s.is_active = 1;
            """;
            cmd.Parameters.AddWithValue("$id", clientId);

            using var reader = cmd.ExecuteReader();
            var list = new List<ScopeResponse>();

            while (reader.Read())
            {
                list.Add(new ScopeResponse
                {
                    Id = reader.GetString(0),
                    Name = reader.GetString(1),
                    Description = reader.IsDBNull(2) ? null : reader.GetString(2),
                    CreatedAt = reader.GetString(3),
                    IsActive = reader.GetInt64(4) == 1
                });
            }

            return list;
        });

        return ApiResult<List<ScopeResponse>>.Ok(scopes);
    }


    /// <summary>
    /// Removes a specified scope from a client.
    /// </summary>
    /// <param name="clientId">The unique identifier of the client from which the scope will be removed. Cannot be null or whitespace.</param>
    /// <param name="scopeId">The unique identifier of the scope to be removed. Cannot be null or whitespace.</param>
    /// <param name="actorUserId">The optional identifier of the user performing the operation, used for auditing purposes.</param>
    /// <param name="ip">The optional IP address of the user performing the operation, used for auditing purposes.</param>
    /// <param name="ua">The optional user agent string of the user performing the operation, used for auditing purposes.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/> that indicates the result of the
    /// operation. Returns a success result if the scope was successfully removed, or a failure result if the scope was
    /// not assigned or already removed.</returns>
    public static ApiResult<MessageResponse> RemoveScopeFromClient(
        string clientId,
        string scopeId,
        AppConfig config,
        string? actorUserId = null,
        string? ip = null,
        string? ua = null)
    {
        if (string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(scopeId))
            return ApiResult<MessageResponse>.Fail("Client ID and Scope ID are required");

        var affected = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                DELETE FROM client_scopes
                WHERE client_id = $cid AND scope_id = $sid;
            """;
            cmd.Parameters.AddWithValue("$cid", clientId);
            cmd.Parameters.AddWithValue("$sid", scopeId);

            return cmd.ExecuteNonQuery();
        });

        if (affected == 0)
            return ApiResult<MessageResponse>.Fail("Scope not assigned or already removed");

        AuditLogger.AuditLog(config, actorUserId, "remove_scope_from_client", $"{clientId}:{scopeId}", ip, ua);

        return ApiResult<MessageResponse>.Ok(new($"Removed scope '{scopeId}' from client '{clientId}'"));
    }


    /// <summary>
    /// Retrieves a list of active scopes assigned to a specified user.
    /// </summary>
    /// <remarks>A scope represents a specific permission or access level assigned to a user.  This method
    /// queries the database for active scopes associated with the user and filters out inactive scopes.</remarks>
    /// <param name="userId">The unique identifier of the user whose scopes are to be retrieved. Cannot be null, empty, or whitespace.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a list of scope names assigned to the user.  If the user has no active
    /// scopes, the list will be empty.  Returns a failure result if the <paramref name="userId"/> is invalid.</returns>
    public static ApiResult<List<string>> ListScopesForUser(string userId)
    {
        if (string.IsNullOrWhiteSpace(userId))
            return ApiResult<List<string>>.Fail("User ID is required");

        var scopes = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT s.name
                FROM user_scopes us
                JOIN scopes s ON us.scope_id = s.id
                WHERE us.user_id = $uid AND us.is_active = 1 AND s.is_active = 1;
            """;
            cmd.Parameters.AddWithValue("$uid", userId);

            using var reader = cmd.ExecuteReader();
            var list = new List<string>();
            while (reader.Read())
                list.Add(reader.GetString(0));

            return list;
        });

        return ApiResult<List<string>>.Ok(scopes);
    }


    /// <summary>
    /// Assigns one or more scopes to a user, ensuring that the scopes are active and not already assigned.
    /// </summary>
    /// <remarks>This method ensures that only active scopes are assigned to the user. If a scope is already
    /// assigned or does not exist, it will be ignored. The operation is logged for auditing purposes if <paramref
    /// name="actorUserId"/> is provided.</remarks>
    /// <param name="userId">The unique identifier of the user to whom the scopes will be assigned. Cannot be null, empty, or whitespace.</param>
    /// <param name="req">An object containing the list of scope IDs to assign. Must include at least one scope ID.</param>
    /// <param name="actorUserId">The unique identifier of the user performing the operation. Optional.</param>
    /// <param name="ip">The IP address of the actor performing the operation. Optional.</param>
    /// <param name="ua">The user agent string of the actor performing the operation. Optional.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/> that indicates the result of the
    /// operation. Returns a success message if at least one scope was assigned, or an error message if no scopes were
    /// assigned.</returns>
    public static ApiResult<MessageResponse> AddScopesToUser(
        string userId,
        AssignScopesRequest req,
        AppConfig config,
        string? actorUserId = null,
        string? ip = null,
        string? ua = null)
    {
        if (string.IsNullOrWhiteSpace(userId))
            return ApiResult<MessageResponse>.Fail("User ID is required");

        if (req.ScopeIds.Count == 0)
            return ApiResult<MessageResponse>.Fail("At least one scope ID is required");

        var added = Db.WithConnection(conn =>
        {
            int added = 0;

            foreach (var scopeId in req.ScopeIds.Distinct())
            {
                string? lookedUpScopeId = null;

                using (var getCmd = conn.CreateCommand())
                {
                    getCmd.CommandText = "SELECT id FROM scopes WHERE id = $sid AND is_active = 1;";
                    getCmd.Parameters.AddWithValue("$sid", scopeId);
                    lookedUpScopeId = getCmd.ExecuteScalar() as string;
                }

                if (lookedUpScopeId is null)
                    continue;

                using var cmd = conn.CreateCommand();
                cmd.CommandText = """
                    INSERT OR IGNORE INTO user_scopes (id, user_id, scope_id, assigned_at, is_active)
                    VALUES ($id, $uid, $sid, datetime('now'), 1);
                """;
                cmd.Parameters.AddWithValue("$id", Guid.NewGuid().ToString());
                cmd.Parameters.AddWithValue("$uid", userId);
                cmd.Parameters.AddWithValue("$sid", lookedUpScopeId);
                added += cmd.ExecuteNonQuery();
            }

            return added;
        });

        if (added == 0)
            return ApiResult<MessageResponse>.Fail("No scopes were assigned — check if they exist or were already assigned");

        AuditLogger.AuditLog(config, actorUserId, "assign_scope_to_user", userId, ip, ua);

        return ApiResult<MessageResponse>.Ok(new($"Assigned {added} scope(s) to user."));
    }

    /// <summary>
    /// Removes a specified scope from a user's active scopes.
    /// </summary>
    /// <remarks>This method deactivates the specified scope for the given user if it is currently active. If
    /// the scope is not assigned to the user or is already inactive, the method returns a failure result. The operation
    /// is logged for auditing purposes if an <paramref name="actorUserId"/> is provided.</remarks>
    /// <param name="userId">The unique identifier of the user from whom the scope will be removed. Cannot be null or whitespace.</param>
    /// <param name="scopeId">The unique identifier of the scope to be removed. Cannot be null or whitespace.</param>
    /// <param name="actorUserId">The unique identifier of the user performing the operation. Optional.</param>
    /// <param name="ip">The IP address of the actor performing the operation. Optional.</param>
    /// <param name="ua">The user agent string of the actor performing the operation. Optional.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/> that indicates the result of the
    /// operation. Returns a success result if the scope was successfully removed, or a failure result with an
    /// appropriate message if the operation could not be completed.</returns>
    public static ApiResult<MessageResponse> RemoveScopeFromUser(
        string userId,
        string scopeId,
        AppConfig config,
        string? actorUserId = null,
        string? ip = null,
        string? ua = null)
    {
        if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(scopeId))
            return ApiResult<MessageResponse>.Fail("User ID and Scope ID are required");

        var affected = Db.WithConnection(conn =>
        {
            string? lookedUpScopeId = null;

            using (var getCmd = conn.CreateCommand())
            {
                getCmd.CommandText = "SELECT id FROM scopes WHERE id = $sid AND is_active = 1;";
                getCmd.Parameters.AddWithValue("$sid", scopeId);
                lookedUpScopeId = getCmd.ExecuteScalar() as string;
            }

            if (lookedUpScopeId is null)
                return 0;

            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                UPDATE user_scopes
                SET is_active = 0
                WHERE user_id = $uid AND scope_id = $sid AND is_active = 1;
            """;
            cmd.Parameters.AddWithValue("$uid", userId);
            cmd.Parameters.AddWithValue("$sid", lookedUpScopeId);

            return cmd.ExecuteNonQuery();
        });

        if (affected == 0)
            return ApiResult<MessageResponse>.Fail("Scope not assigned or already removed");

        AuditLogger.AuditLog(config, actorUserId, "remove_scope_from_user", $"{userId}:{scopeId}", ip, ua);

        return ApiResult<MessageResponse>.Ok(new($"Removed scope '{scopeId}' from user '{userId}'."));
    }
}
