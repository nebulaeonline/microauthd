namespace microauthd.Data;

public static class RoleStore
{
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
