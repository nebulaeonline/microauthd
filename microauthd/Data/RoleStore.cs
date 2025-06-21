using madTypes.Api.Common;

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
                ORDER BY name
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
}
