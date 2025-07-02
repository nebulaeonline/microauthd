using madTypes.Api.Common;
using madTypes.Api.Responses;
using madTypes.Common;
using microauthd.Common;
using Microsoft.Data.Sqlite;
using Serilog;

namespace microauthd.Data;

public static class PermissionStore
{
    /// <summary>
    /// Creates a new permission record in the database and retrieves the created permission object.
    /// </summary>
    /// <remarks>This method attempts to insert a new permission record into the database. If the insertion is
    /// successful, it retrieves the created permission object based on the provided <paramref name="permissionId"/>. If
    /// the insertion fails (e.g., due to a database constraint violation), the method returns <see
    /// langword="null"/>.</remarks>
    /// <param name="permissionId">The unique identifier for the permission. Must not be null or empty.</param>
    /// <param name="name">The name of the permission. Must not be null or empty.</param>
    /// <returns>A <see cref="PermissionObject"/> representing the newly created permission if the operation succeeds; otherwise,
    /// <see langword="null"/>.</returns>
    public static PermissionObject? CreatePermission(string permissionId, string name)
    {
        var success = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                INSERT INTO permissions (id, name, created_at, is_active)
                VALUES ($id, $name, datetime('now'), 1);
            """;
            cmd.Parameters.AddWithValue("$id", permissionId);
            cmd.Parameters.AddWithValue("$name", name.Trim());
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
            return null;

        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT id, name FROM permissions WHERE id = $id;
            """;
            cmd.Parameters.AddWithValue("$id", permissionId);

            using var reader = cmd.ExecuteReader();
            if (!reader.Read())
                return null;

            return new PermissionObject
            {
                Id = reader.GetString(0),
                Name = reader.GetString(1).Trim()
            };
        });
    }

    /// <summary>
    /// Updates the specified permission in the database and returns the updated permission object.
    /// </summary>
    /// <remarks>This method updates the permission's name and modification timestamp in the database. If the
    /// update operation fails (e.g., the permission does not exist), the method returns <see
    /// langword="null"/>.</remarks>
    /// <param name="permissionId">The unique identifier of the permission to update.</param>
    /// <param name="updated">The updated <see cref="PermissionObject"/> containing the new values for the permission.</param>
    /// <returns>The updated <see cref="PermissionObject"/> if the update operation succeeds; otherwise, <see langword="null"/>.</returns>
    public static PermissionObject? UpdatePermission(string permissionId, PermissionObject updated)
    {
        var success = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                UPDATE permissions
                SET name = $name,
                    modified_at = datetime('now')
                WHERE id = $id;
            """;
            cmd.Parameters.AddWithValue("$name", updated.Name.Trim());
            cmd.Parameters.AddWithValue("$id", permissionId);
            return cmd.ExecuteNonQuery() == 1;
        });

        if (!success)
            return null;

        return GetPermissionById(permissionId);
    }

    /// <summary>
    /// Determines whether a permission name already exists in the database, excluding the specified permission ID.
    /// </summary>
    /// <remarks>This method performs a case-sensitive check against the database to determine if the
    /// specified permission name is already in use. Ensure that both <paramref name="permissionId"/> and <paramref
    /// name="name"/> are valid, non-empty strings before calling this method.</remarks>
    /// <param name="permissionId">The unique identifier of the permission to exclude from the check. Cannot be null, empty, or whitespace.</param>
    /// <param name="name">The name of the permission to check for existence. Cannot be null, empty, or whitespace.</param>
    /// <returns><see langword="true"/> if a permission with the specified name exists in the database and does not match the
    /// given permission ID; otherwise, <see langword="false"/>.</returns>
    public static bool DoesPermissionNameExist(string permissionId, string name)
    {
        if (string.IsNullOrWhiteSpace(permissionId) || string.IsNullOrWhiteSpace(name))
            return false;
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT COUNT(*) FROM permissions WHERE id != $id AND name = $name;
            """;
            cmd.Parameters.AddWithValue("$id", permissionId);
            cmd.Parameters.AddWithValue("$name", name.Trim());
            var result = cmd.ExecuteScalar();
            return Convert.ToInt32(result) > 0;
        });
    }

    /// <summary>
    /// Retrieves a list of all permissions from the database, ordered by name.
    /// </summary>
    /// <remarks>This method queries the database to fetch all permissions and returns them as a collection of
    /// <see cref="PermissionObject"/> objects. The permissions are sorted alphabetically by their name.</remarks>
    /// <returns>A list of <see cref="PermissionObject"/> instances, where each object represents a permission with its
    /// associated ID and name. Returns an empty list if no permissions are found.</returns>
    public static List<PermissionObject> ListAllPermissions()
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT id, name FROM permissions ORDER BY name;";
            using var reader = cmd.ExecuteReader();
            var results = new List<PermissionObject>();
            while (reader.Read())
            {
                results.Add(new PermissionObject
                {
                    Id = reader.GetString(0),
                    Name = reader.GetString(1).Trim(),
                });
            }
            return results;
        });
    }

    /// <summary>
    /// Retrieves a paginated list of active permissions from the database.
    /// </summary>
    /// <remarks>Permissions are ordered alphabetically by their name. Only permissions marked as active are
    /// included in the results.</remarks>
    /// <param name="offset">The zero-based index of the first permission to retrieve. Must be non-negative.</param>
    /// <param name="limit">The maximum number of permissions to retrieve. Must be greater than zero.</param>
    /// <returns>A list of <see cref="PermissionObject"/> instances representing active permissions. The list will be empty if no
    /// active permissions are found within the specified range.</returns>
    public static List<PermissionObject> ListPermissions(int offset = 0, int limit = 50)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT id, name
                FROM permissions
                WHERE is_active = 1
                ORDER BY name
                LIMIT $limit OFFSET $offset
            """;
            cmd.Parameters.AddWithValue("$limit", limit);
            cmd.Parameters.AddWithValue("$offset", offset);

            using var reader = cmd.ExecuteReader();
            var results = new List<PermissionObject>();
            while (reader.Read())
            {
                results.Add(new PermissionObject
                {
                    Id = reader.GetString(0),
                    Name = reader.GetString(1).Trim(),
                });
            }
            return results;
        });
    }

    /// <summary>
    /// Retrieves an active permission object by its unique identifier.
    /// </summary>
    /// <remarks>This method queries the database for a permission with the specified identifier that is
    /// marked as active. If the identifier is invalid or no active permission matches the given identifier, the method
    /// returns <see langword="null"/>.</remarks>
    /// <param name="pId">The unique identifier of the permission to retrieve. This value cannot be null, empty, or consist solely of
    /// whitespace.</param>
    /// <returns>A <see cref="PermissionObject"/> representing the active permission with the specified identifier,  or <see
    /// langword="null"/> if no matching active permission is found.</returns>
    public static PermissionObject? GetPermissionById(string pId)
    {
        if (string.IsNullOrWhiteSpace(pId))
            return null;

        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT id, name FROM permissions WHERE id = @id AND is_active = 1;";
            cmd.Parameters.AddWithValue("@id", pId);
            using var reader = cmd.ExecuteReader();
            if (reader.Read())
            {
                return new PermissionObject
                {
                    Id = reader.GetString(0),
                    Name = reader.GetString(1).Trim()
                };
            }
            return null;
        });
    }

    /// <summary>
    /// Retrieves the unique identifier of a permission based on its name.
    /// </summary>
    /// <remarks>This method queries the database to find the permission ID associated with the given name. If
    /// no matching permission is found, the method returns <see langword="null"/>.</remarks>
    /// <param name="name">The name of the permission to look up. This value cannot be null or empty.</param>
    /// <returns>The unique identifier of the permission as a string, or <see langword="null"/> if no permission with the
    /// specified name exists.</returns>
    public static string? GetPermissionIdByName(string name)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT id FROM permissions WHERE name = $name LIMIT 1;";
            cmd.Parameters.AddWithValue("$name", name.Trim());

            var result = cmd.ExecuteScalar();
            return result == null ? null : Convert.ToString(result)?.Trim();
        });
    }

    /// <summary>
    /// Retrieves a list of active permissions assigned to the specified role.
    /// </summary>
    /// <remarks>This method queries the database to fetch permissions associated with the specified role.
    /// Only permissions marked as active are included in the result.</remarks>
    /// <param name="roleId">The unique identifier of the role for which permissions are being retrieved. Must not be null, empty, or consist
    /// solely of whitespace.</param>
    /// <returns>A list of <see cref="PermissionDto"/> objects representing the active permissions assigned to the role. Returns
    /// an empty list if the <paramref name="roleId"/> is null, empty, or whitespace, or if no active permissions are
    /// assigned to the role.</returns>
    public static List<PermissionDto> GetAssignedPermissionDtos(string roleId)
    {
        if (string.IsNullOrWhiteSpace(roleId))
            return new List<PermissionDto>();
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT p.id, p.name FROM permissions p " +
                              "JOIN role_permissions rp ON p.id = rp.permission_id " +
                              "WHERE rp.role_id = @roleId AND p.is_active = 1;";
            cmd.Parameters.AddWithValue("@roleId", roleId);
            using var reader = cmd.ExecuteReader();
            var permissions = new List<PermissionDto>();
            while (reader.Read())
            {
                permissions.Add(new PermissionDto
                {
                    Id = reader.GetString(0),
                    Name = reader.GetString(1).Trim()
                });
            }
            return permissions;
        });
    }

    /// <summary>
    /// Retrieves a list of active permissions from the database.
    /// </summary>
    /// <remarks>This method queries the database for permissions that are marked as active and returns them
    /// as a list of <see cref="PermissionDto"/> objects. Each object contains the ID and name of a
    /// permission.</remarks>
    /// <returns>A list of <see cref="PermissionDto"/> objects representing active permissions. If no active permissions are
    /// found, the list will be empty.</returns>
    public static List<PermissionDto> GetAllPermissionDtos()
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT id, name FROM permissions WHERE is_active = 1;";
            using var reader = cmd.ExecuteReader();
            var permissions = new List<PermissionDto>();
            while (reader.Read())
            {
                permissions.Add(new PermissionDto
                {
                    Id = reader.GetString(0),
                    Name = reader.GetString(1).Trim()
                });
            }
            return permissions;
        });
    }

    /// <summary>
    /// Deletes a permission record from the database based on the specified permission ID.
    /// </summary>
    /// <remarks>This method executes a database operation to remove the permission record associated with the
    /// given ID. Ensure that the provided <paramref name="permissionId"/> corresponds to an existing record in the
    /// database.</remarks>
    /// <param name="permissionId">The unique identifier of the permission to delete. This value cannot be null or empty.</param>
    /// <returns><see langword="true"/> if the permission was successfully deleted; otherwise, <see langword="false"/>.</returns>
    public static bool DeletePermission(string permissionId)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "DELETE FROM permissions WHERE id = $id;";
            cmd.Parameters.AddWithValue("$id", permissionId);
            return cmd.ExecuteNonQuery() > 0;            
        });
    }

    /// <summary>
    /// Assigns a permission to a role if both the permission and role are active.
    /// </summary>
    /// <remarks>This method checks the active status of both the role and the permission before attempting
    /// the assignment. If either the role or the permission is inactive, the assignment will not proceed. The
    /// assignment is performed using an "INSERT OR IGNORE" operation, ensuring that duplicate assignments are
    /// avoided.</remarks>
    /// <param name="permissionId">The unique identifier of the permission to assign. Must correspond to an active permission.</param>
    /// <param name="roleId">The unique identifier of the role to which the permission will be assigned. Must correspond to an active role.</param>
    /// <returns><see langword="true"/> if the permission was successfully assigned to the role;  otherwise, <see
    /// langword="false"/> if the role or permission is inactive, or if the assignment fails.</returns>
    public static bool AssignPermissionToRole(string permissionId, string roleId)
    {
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
                return false;

            int assigned = 0;

            string? lookedUpPermId = null;
            using (var cmd = conn.CreateCommand())
            {
                cmd.CommandText = "SELECT id FROM permissions WHERE id = $pid AND is_active = 1;";
                cmd.Parameters.AddWithValue("$pid", permissionId);
                lookedUpPermId = cmd.ExecuteScalar() as string;
            }

            if (lookedUpPermId is null)
                return false;

            using var cmdInsert = conn.CreateCommand();
            cmdInsert.CommandText = """
                INSERT OR IGNORE INTO role_permissions (id, role_id, permission_id, assigned_at)
                VALUES ($id, $roleId, $permId, datetime('now'));
            """;
            cmdInsert.Parameters.AddWithValue("$id", Guid.NewGuid().ToString());
            cmdInsert.Parameters.AddWithValue("$roleId", lookedUpRoleId);
            cmdInsert.Parameters.AddWithValue("$permId", lookedUpPermId);

            assigned = cmdInsert.ExecuteNonQuery();

            return assigned > 0;
        });
    }

    /// <summary>
    /// Removes a permission from a role in the system.
    /// </summary>
    /// <remarks>This method performs validation to ensure that both the role and permission are active before
    /// attempting the removal. If either the role or permission is inactive or does not exist, the method will return
    /// <see langword="false"/>.</remarks>
    /// <param name="permissionId">The unique identifier of the permission to be removed. Must correspond to an active permission.</param>
    /// <param name="roleId">The unique identifier of the role from which the permission will be removed. Must correspond to an active role.</param>
    /// <returns><see langword="true"/> if the permission was successfully removed from the role; otherwise, <see
    /// langword="false"/> if the role or permission does not exist, is inactive, or the removal operation failed.</returns>
    public static bool RemovePermissionFromRole(string permissionId, string roleId)
    {
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
                return false;

            using var cmdDel = conn.CreateCommand();
            cmdDel.CommandText = """
                    DELETE FROM role_permissions
                    WHERE role_id = $rid AND permission_id = $pid;
                """;
            cmdDel.Parameters.AddWithValue("$rid", lookedUpRoleId);
            cmdDel.Parameters.AddWithValue("$pid", lookedUpPermId);

            var removed = cmdDel.ExecuteNonQuery();
            return removed > 0;            
        });
    }

    /// <summary>
    /// Retrieves the effective permissions assigned to a user based on their active roles.
    /// </summary>
    /// <remarks>This method queries the database to determine the permissions associated with the user's
    /// active roles.  Only permissions, roles, and user-role associations marked as active are considered.</remarks>
    /// <param name="userId">The unique identifier of the user whose permissions are being retrieved. Cannot be null or empty.</param>
    /// <returns>A list of <see cref="PermissionObject"/> representing the distinct permissions assigned to the user.  The list
    /// will be empty if the user has no active permissions.</returns>
    public static List<PermissionObject> GetEffectivePermissionsForUser(string userId)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT DISTINCT p.id, p.name
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
            var results = new List<PermissionObject>();
            while (reader.Read())
            {
                results.Add(new PermissionObject
                {
                    Id = reader.GetString(0),
                    Name = reader.GetString(1).Trim()
                });
            }

            return results;
        });
    }

    /// <summary>
    /// Determines whether the specified user has the specified permission.
    /// </summary>
    /// <remarks>This method checks the user's active roles and their associated permissions to determine 
    /// whether the user has the specified permission. The user, roles, and permissions must all  be marked as active
    /// for the permission to be granted.</remarks>
    /// <param name="userId">The unique identifier of the user. Cannot be null or empty.</param>
    /// <param name="permissionId">The unique identifier of the permission. Cannot be null or empty.</param>
    /// <returns><see langword="true"/> if the user has the specified permission and all related entities  (user, roles,
    /// permissions) are active; otherwise, <see langword="false"/>.</returns>
    public static bool UserHasPermission(string userId, string permissionId)
    {
        return Db.WithConnection(conn =>
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
    }

    public static List<PermissionObject> GetPermissionsForRole(string roleId)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT p.id, p.name
                FROM role_permissions rp
                JOIN roles r ON rp.role_id = r.id
                JOIN permissions p ON rp.permission_id = p.id
                WHERE r.id = $rid AND r.is_active = 1 AND p.is_active = 1;
            """;
            cmd.Parameters.AddWithValue("$rid", roleId);

            using var reader = cmd.ExecuteReader();
            var results = new List<PermissionObject>();
            while (reader.Read())
            {
                results.Add(new PermissionObject
                {
                    Id = reader.GetString(0),
                    Name = reader.GetString(1).Trim()
                });
            }

            return results;
        });
    }

    /// <summary>
    /// Retrieves the count of active permissions from the database.
    /// </summary>
    /// <remarks>This method executes a query to count the number of active permissions, where the 
    /// permissions are marked as active in the database. The count is returned as an integer.</remarks>
    /// <returns>The total number of active permissions in the database.</returns>
    public static int GetPermissionCount()
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT COUNT(*) FROM permissions WHERE is_active = 1;";
            return Convert.ToInt32(cmd.ExecuteScalar());
        });
    }
}
