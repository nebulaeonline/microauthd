using madTypes.Api.Common;

namespace microauthd.Data;

public static class PermissionStore
{
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
                    Name = reader.GetString(1),
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
                    Name = reader.GetString(1)
                };
            }
            return null;
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
                    Name = reader.GetString(1)
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
                    Name = reader.GetString(1)
                });
            }
            return permissions;
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
