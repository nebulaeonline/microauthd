using madTypes.Api.Common;
using madTypes.Api.Responses;
using madTypes.Common;
using microauthd.Common;
using Microsoft.Data.Sqlite;
using Serilog;
using System.Data;
using System.Text.Json.Serialization;
using System.Xml.Linq;

namespace microauthd.Data;

public static class RoleStore
{    
    /// <summary>
    /// Creates a new role in the database and retrieves the created role object.
    /// </summary>
    /// <remarks>This method inserts a new role into the database and retrieves the created role object. If
    /// the insertion fails (e.g., due to a database constraint violation), the method returns <see
    /// langword="null"/>.</remarks>
    /// <param name="roleId">The unique identifier for the role. Must not be null or empty.</param>
    /// <param name="name">The name of the role. Must not be null or empty.</param>
    /// <param name="description">The description of the role. Can be null, in which case an empty string will be stored.</param>
    /// <returns>A <see cref="RoleObject"/> representing the newly created role, or <see langword="null"/> if the role could not
    /// be created.</returns>
    public static RoleObject? CreateRole(string roleId, string name, string description)
    {
        var success = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                INSERT INTO roles (id, name, description, created_at, modified_at, is_active)
                VALUES ($id, $name, $desc, datetime('now'), datetime('now'), 1);
            """;
            cmd.Parameters.AddWithValue("$id", roleId);
            cmd.Parameters.AddWithValue("$name", name.Trim());
            cmd.Parameters.AddWithValue("$desc", description.Trim() ?? "");

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
            cmd.CommandText = "SELECT id, name, description, is_protected FROM roles WHERE id = $id;";
            cmd.Parameters.AddWithValue("$id", roleId);
            using var reader = cmd.ExecuteReader();

            if (reader.Read())
            {
                return new RoleObject
                {
                    Id = reader.GetString(0),
                    Name = reader.GetString(1).Trim(),
                    Description = reader.IsDBNull(2) ? null : reader.GetString(2).Trim(),
                    IsProtected = reader.GetInt32(3) == 1
                };
            }
            return null;
        });
    }

    /// <summary>
    /// Updates the specified role with new values and returns the updated role object.
    /// </summary>
    /// <remarks>This method updates the role's name, description, and modification timestamp in the database.
    /// Protected roles (roles with <c>is_protected</c> set to <see langword="true"/>) cannot be updated. If the role
    /// does not exist or the update fails, the method returns <see langword="null"/>.</remarks>
    /// <param name="roleId">The unique identifier of the role to update. Cannot be null or empty.</param>
    /// <param name="updated">An object containing the updated values for the role. The <see cref="RoleObject.Name"/> property must not be
    /// null or empty if it is to be updated. The <see cref="RoleObject.Description"/> property can be null to leave the
    /// description unchanged.</param>
    /// <returns>The updated <see cref="RoleObject"/> if the update is successful; otherwise, <see langword="null"/>.</returns>
    public static RoleObject? UpdateRole(string roleId, RoleObject updated)
    {
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
            cmd.Parameters.AddWithValue("$name", updated.Name.Trim() ?? "");
            cmd.Parameters.AddWithValue("$desc", (object?)updated.Description?.Trim() ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$id", roleId);
            return cmd.ExecuteNonQuery() == 1;
        });

        if (!success)
            return null;

        return GetRoleById(roleId);
    }

    /// <summary>
    /// Determines whether a name conflict exists in the roles database.
    /// </summary>
    /// <remarks>A name conflict occurs when the specified <paramref name="name"/> is already present in the
    /// roles database and is associated with an entity other than the one identified by <paramref
    /// name="searcherId"/>.</remarks>
    /// <param name="searcherId">The unique identifier of the entity performing the search. This ID is excluded from the conflict check.</param>
    /// <param name="name">The name to check for conflicts in the roles database.</param>
    /// <returns><see langword="true"/> if a conflict exists (i.e., the specified name is already associated with another entity
    /// in the database); otherwise, <see langword="false"/>.</returns>
    public static bool DoesNameConflictExist(string searcherId, string name)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                    SELECT COUNT(*) FROM roles
                    WHERE name = $name AND id != $id;
                """;
            cmd.Parameters.AddWithValue("$name", name.Trim());
            cmd.Parameters.AddWithValue("$id", searcherId);
            return Convert.ToInt32(cmd.ExecuteScalar()) > 0;
        });
    }

    /// <summary>
    /// Retrieves a list of all roles from the database.
    /// </summary>
    /// <remarks>The roles are ordered alphabetically by their name. Each role includes its ID, name,
    /// description,  protection status, and active status. If a role's description is not set in the database, the 
    /// description will be <see langword="null"/>.</remarks>
    /// <returns>A list of <see cref="RoleObject"/> instances representing all roles in the database.  The list will be empty if
    /// no roles are found.</returns>
    public static List<RoleObject> ListAllRoles()
    {
        return Db.WithConnection(conn =>
        {
            var roles = new List<RoleObject>();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT id, name, description, is_protected, is_active FROM roles
                ORDER BY name
            """;
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                roles.Add(new RoleObject
                {
                    Id = reader.GetString(0),
                    Name = reader.GetString(1).Trim(),
                    Description = reader.IsDBNull(2) ? null : reader.GetString(2).Trim(),
                    IsProtected = reader.GetBoolean(3),
                    IsActive = reader.GetBoolean(4)
                });
            }
            return roles;
        });
    }

    /// <summary>
    /// Retrieves a paginated list of roles from the database.
    /// </summary>
    /// <remarks>Roles are ordered alphabetically by their name. Use the <paramref name="offset"/> and 
    /// <paramref name="limit"/> parameters to control pagination.</remarks>
    /// <param name="offset">The zero-based index of the first role to retrieve. Must be greater than or equal to 0.</param>
    /// <param name="limit">The maximum number of roles to retrieve. Must be greater than 0.</param>
    /// <returns>A list of <see cref="RoleObject"/> instances representing the roles in the database. The list will be empty if
    /// no roles match the specified pagination parameters.</returns>
    public static List<RoleObject> ListRoles(int offset = 0, int limit = 50)
    {
        return Db.WithConnection(conn =>
        {
            var roles = new List<RoleObject>();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT id, name, description, is_protected, is_active FROM roles
                WHERE is_active = 1 ORDER BY name
                LIMIT $limit OFFSET $offset
            """;
            cmd.Parameters.AddWithValue("$limit", limit);
            cmd.Parameters.AddWithValue("$offset", offset);
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                roles.Add(new RoleObject
                {
                    Id = reader.GetString(0),
                    Name = reader.GetString(1).Trim(),
                    Description = reader.IsDBNull(2) ? null : reader.GetString(2).Trim(),
                    IsProtected = reader.GetBoolean(3),
                    IsActive = reader.GetBoolean(4)
                });
            }
            return roles;
        });
    }

    /// <summary>
    /// Retrieves a role by its unique identifier.
    /// </summary>
    /// <remarks>This method queries the database to retrieve the role information associated with the given
    /// identifier. If the <paramref name="roleId"/> is invalid (null, empty, or whitespace), the method returns <see
    /// langword="null"/>.</remarks>
    /// <param name="roleId">The unique identifier of the role to retrieve. This value cannot be null, empty, or consist solely of
    /// whitespace.</param>
    /// <returns>A <see cref="RoleObject"/> representing the role with the specified identifier, or <see langword="null"/> if no
    /// matching role is found.</returns>
    public static RoleObject? GetRoleById(string roleId)
    {
        if (string.IsNullOrWhiteSpace(roleId))
            return null;
        
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT id, name, description, is_protected, is_active FROM roles
                WHERE id = $rid
            """;
            cmd.Parameters.AddWithValue("$rid", roleId);
            using var reader = cmd.ExecuteReader();
            if (reader.Read())
            {
                return new RoleObject
                {
                    Id = reader.GetString(0),
                    Name = reader.GetString(1).Trim(),
                    Description = reader.IsDBNull(2) ? null : reader.GetString(2).Trim(),
                    IsProtected = reader.GetBoolean(3),
                    IsActive = reader.GetBoolean(4)
                };
            }
            return null;
        });
    }

    /// <summary>
    /// Retrieves the unique identifier of a role based on its name.
    /// </summary>
    /// <remarks>This method queries the database to find the role ID associated with the given name. Ensure
    /// that the database connection is properly configured and accessible.</remarks>
    /// <param name="name">The name of the role to search for. Cannot be null or empty.</param>
    /// <returns>The unique identifier of the role as a string, or <see langword="null"/> if no role with the specified name
    /// exists.</returns>
    public static string? GetRoleIdByName(string name)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT id FROM roles WHERE name = $name LIMIT 1;";
            cmd.Parameters.AddWithValue("$name", name.Trim());

            var result = cmd.ExecuteScalar();
            return result == null ? null : Convert.ToString(result);
        });
    }

    /// <summary>
    /// Retrieves a list of active roles associated with the specified user.
    /// </summary>
    /// <remarks>This method queries the database to retrieve roles that are both active and
    /// associated with the user. Ensure the database connection is properly configured before calling this
    /// method.</remarks>
    /// <param name="userId">The unique identifier of the user whose roles are to be retrieved. Must not be <see langword="null"/> or
    /// empty.</param>
    /// <returns>A list of strings representing the IDs of active roles assigned to the user. Returns an empty list if the
    /// user has no active roles.</returns>
    public static List<string> GetUserRoles(string userId)
    {
        return Db.WithConnection(conn =>
        {
            var roles = new List<string>();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT r.id FROM user_roles ur
                JOIN roles r ON ur.role_id = r.id
                WHERE ur.user_id = $uid AND ur.is_active = 1 AND r.is_active = 1
            """;
            cmd.Parameters.AddWithValue("$uid", userId);
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
                roles.Add(reader.GetString(0).Trim());
            return roles;
        });
    }

    /// <summary>
    /// Deletes a role from the database if it is not marked as protected.
    /// </summary>
    /// <remarks>This method deletes a role only if the role is not marked as protected in the database.
    /// Protected roles cannot be deleted.</remarks>
    /// <param name="roleId">The unique identifier of the role to delete. Cannot be null or empty.</param>
    /// <returns><see langword="true"/> if the role was successfully deleted; otherwise, <see langword="false"/>. </returns>
    public static bool DeleteRole(string roleId)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "DELETE FROM roles WHERE id = $id AND is_protected = 0;";
            cmd.Parameters.AddWithValue("$id", roleId);

            return cmd.ExecuteNonQuery() > 0;            
        });
    }

    /// <summary>
    /// Removes the specified role from the specified user.
    /// </summary>
    /// <remarks>This method performs a database operation to remove the association between the user and the
    /// role. Ensure that the provided <paramref name="userId"/> and <paramref name="roleId"/> correspond to valid
    /// entries in the database.</remarks>
    /// <param name="userId">The unique identifier of the user from whom the role will be removed. Cannot be null or empty.</param>
    /// <param name="roleId">The unique identifier of the role to be removed from the user. Cannot be null or empty.</param>
    /// <returns><see langword="true"/> if the role was successfully removed from the user; otherwise, <see langword="false"/> if
    /// the user or role does not exist, or if the role was not assigned to the user.</returns>
    public static bool RemoveRoleFromUser(string userId, string roleId)
    {
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
                return false;

            using var deleteCmd = conn.CreateCommand();
            deleteCmd.CommandText = """
                DELETE FROM user_roles
                WHERE user_id = $uid AND role_id = $rid;
            """;
            deleteCmd.Parameters.AddWithValue("$uid", userId);
            deleteCmd.Parameters.AddWithValue("$rid", roleId);
            var removed = deleteCmd.ExecuteNonQuery();

            if (removed == 0)
                return false;

            return true;
        });
    }

    /// <summary>
    /// Assigns a role to a user in the system.
    /// </summary>
    /// <remarks>This method performs the following operations: <list type="bullet">
    /// <item><description>Validates the existence of the specified user and role in the database.</description></item>
    /// <item><description>Assigns the role to the user by inserting a record into the user_roles
    /// table.</description></item> </list> The method returns <see langword="false"/> if either the user or the role
    /// does not exist.</remarks>
    /// <param name="userId">The unique identifier of the user to whom the role will be assigned. Cannot be null or empty.</param>
    /// <param name="roleId">The unique identifier of the role to assign to the user. Cannot be null or empty.</param>
    /// <returns><see langword="true"/> if the role was successfully assigned to the user;  otherwise, <see langword="false"/> if
    /// the user or role does not exist.</returns>
    public static bool AddRoleToUser(string userId, string roleId)
    {
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
                return false;

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

            return true;
        });
    }

    /// <summary>
    /// Retrieves the count of active roles from the database.
    /// </summary>
    /// <remarks>This method queries the database to count the number of roles marked as active. It assumes
    /// that the database connection and schema are properly configured.</remarks>
    /// <returns>The total number of active roles in the database.</returns>
    public static int GetRoleCount()
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT COUNT(*) FROM roles WHERE is_active = 1;";
            return Convert.ToInt32(cmd.ExecuteScalar());
        });
    }

    /// <summary>
    /// Retrieves a list of active roles from the database.
    /// </summary>
    /// <remarks>This method queries the database for roles that are marked as active and returns them as a
    /// list of  <see cref="RoleDto"/> objects. Each role includes its identifier and name.</remarks>
    /// <returns>A list of <see cref="RoleDto"/> objects representing active roles. Returns an empty list if no active roles are
    /// found.</returns>
    public static List<RoleDto> GetAllRoleDtos()
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT id, name FROM roles WHERE is_active = 1";
            using var reader = cmd.ExecuteReader();
            var roles = new List<RoleDto>();
            while (reader.Read())
            {
                roles.Add(new RoleDto
                {
                    Id = reader.GetString(0),
                    Name = reader.GetString(1).Trim()
                });
            }
            return roles;
        });
    }

    /// <summary>
    /// Retrieves a list of active roles assigned to the specified user.
    /// </summary>
    /// <remarks>This method queries the database to retrieve roles that are both active and assigned to the
    /// user. The roles are filtered based on the user's active assignments and the active status of the
    /// roles.</remarks>
    /// <param name="userId">The unique identifier of the user whose roles are to be retrieved.  This parameter cannot be null, empty, or
    /// consist solely of whitespace.</param>
    /// <returns>A list of <see cref="RoleDto"/> objects representing the active roles assigned to the user. If the <paramref
    /// name="userId"/> is null, empty, or consists solely of whitespace,  an empty list is returned.</returns>
    public static List<RoleDto> GetAssignedRolesDto(string userId)
    {
        if (string.IsNullOrWhiteSpace(userId))
            return new List<RoleDto>();

        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT r.id, r.name FROM user_roles ur
                JOIN roles r ON ur.role_id = r.id
                WHERE ur.user_id = $uid AND ur.is_active = 1 AND r.is_active = 1
            """;
            cmd.Parameters.AddWithValue("$uid", userId);
            using var reader = cmd.ExecuteReader();
            var roles = new List<RoleDto>();
            while (reader.Read())
            {
                roles.Add(new RoleDto
                {
                    Id = reader.GetString(0),
                    Name = reader.GetString(1).Trim()
                });
            }
            return roles;
        });
    }
}
