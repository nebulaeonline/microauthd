using madTypes.Api.Common;
using System.Text.Json.Serialization;

namespace microauthd.Data;

public static class RoleStore
{
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
                    Name = reader.GetString(1),
                    Description = reader.IsDBNull(2) ? null : reader.GetString(2),
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
                    Name = reader.GetString(1),
                    Description = reader.IsDBNull(2) ? null : reader.GetString(2),
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
            cmd.Parameters.AddWithValue("$name", name);

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
                roles.Add(reader.GetString(0));
            return roles;
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
                    Name = reader.GetString(1)
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
                    Name = reader.GetString(1)
                });
            }
            return roles;
        });
    }
}
