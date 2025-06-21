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

        var roleId = Guid.NewGuid().ToString();
        var success = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                INSERT INTO roles (id, name, description, created_at, modified_at, is_active)
                VALUES ($id, $name, $desc, datetime('now'), datetime('now'), 1);
            """;
            cmd.Parameters.AddWithValue("$id", roleId);
            cmd.Parameters.AddWithValue("$name", name);
            cmd.Parameters.AddWithValue("$desc", description ?? "");

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
            return ApiResult<RoleObject>.Fail("Role creation failed (maybe duplicate?)");

        AuditLogger.AuditLog(
            config: config,
            userId: userId,
            action: "role_created",
            target: name,
            ipAddress: ip,
            userAgent: ua
        );

        var role = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT id, name, description, is_protected FROM roles WHERE id = $id;";
            cmd.Parameters.AddWithValue("$id", roleId);
            using var reader = cmd.ExecuteReader();

            if (reader.Read())
            {
                return new RoleObject
                {
                    Id = reader.GetString(0),
                    Name = reader.GetString(1),
                    Description = reader.IsDBNull(2) ? null : reader.GetString(2),
                    IsProtected = reader.GetInt32(3) == 1
                };
            }
            return null;
        });

        if (role is null)
            return ApiResult<RoleObject>.Fail("Role created but could not be retrieved from the database.");

        return ApiResult<RoleObject>.Ok(role);
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

        // Check for name collision only if name is being updated
        if (!string.IsNullOrWhiteSpace(updated.Name))
        {
            var conflict = Db.WithConnection(conn =>
            {
                using var cmd = conn.CreateCommand();
                cmd.CommandText = """
                    SELECT COUNT(*) FROM roles
                    WHERE name = $name AND id != $id;
                """;
                cmd.Parameters.AddWithValue("$name", updated.Name);
                cmd.Parameters.AddWithValue("$id", id);
                return Convert.ToInt32(cmd.ExecuteScalar()) > 0;
            });

            if (conflict)
                return ApiResult<RoleObject>.Fail("Another role already uses that name.");
        }

        // Perform the update dynamically
        var success = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                UPDATE roles
                SET
                    name = COALESCE(NULLIF($name, ''), name),
                    description = COALESCE($desc, description),
                    modified_at = datetime('now')
                WHERE id = $id AND is_protected = 0;
            """;
            cmd.Parameters.AddWithValue("$name", updated.Name ?? "");
            cmd.Parameters.AddWithValue("$desc", (object?)updated.Description ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$id", id);
            return cmd.ExecuteNonQuery() == 1;
        });

        if (!success)
            return ApiResult<RoleObject>.Fail("Role update failed. Role may be protected or not found.");

        return GetRoleById(id); // re-fetch using existing method
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
            var list = new List<RoleObject>();
            while (reader.Read())
            {
                list.Add(new RoleObject
                {
                    Id = reader.GetString(0),
                    Name = reader.GetString(1),
                    Description = reader.IsDBNull(2) ? null : reader.GetString(2),
                    IsProtected = reader.GetInt32(3) == 1
                });
            }

            return list;
        });

        return ApiResult<List<RoleObject>>.Ok(roles);
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
        var role = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT id, name, description, is_protected
                FROM roles
                WHERE id = $id;
            """;
            cmd.Parameters.AddWithValue("$id", id);
            using var reader = cmd.ExecuteReader();
            if (!reader.Read()) return null;

            return new RoleObject
            {
                Id = reader.GetString(0),
                Name = reader.GetString(1),
                Description = reader.GetString(2),
                IsProtected = reader.GetBoolean(3)
            };
        });

        return role is null
            ? ApiResult<RoleObject>.NotFound($"Role '{id}' not found.")
            : ApiResult<RoleObject>.Ok(role);
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

            return ApiResult<MessageResponse>.Ok(new(true, $"Assigned role '{roleId}' to user '{userId}'"));
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
        var deleted = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "DELETE FROM roles WHERE id = $id AND is_protected = 0;";
            cmd.Parameters.AddWithValue("$id", roleId);

            try
            {
                return cmd.ExecuteNonQuery() > 0;
            }
            catch (SqliteException ex)
            {
                Log.Error(ex, "Failed to delete role {RoleId}", roleId);
                return false;
            }
        });

        if (!deleted)
            return ApiResult<MessageResponse>.Fail("Failed to delete role (not found or constraint violation)");

        AuditLogger.AuditLog(config, userId, "delete_role", roleId, ip, ua);
        return ApiResult<MessageResponse>.Ok(new(true, $"Role '{roleId}' deleted"));
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
                new(true, $"Removed role '{roleId}' from user '{userId}'"));
        });
    }

    /// <summary>
    /// Retrieves the total number of roles currently stored in the system.
    /// </summary>
    /// <returns>The total count of roles as an integer. Returns 0 if no roles are stored.</returns>
    public static int GetRoleCount() => RoleStore.GetRoleCount();
}
