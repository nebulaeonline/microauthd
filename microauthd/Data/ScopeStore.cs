namespace microauthd.Data
{
    public static class ScopeStore
    {
        /// <summary>
        /// Retrieves a list of active scopes associated with the specified user.
        /// </summary>
        /// <remarks>This method queries the database to retrieve scopes that are both active for the user
        /// and globally active. Ensure the database connection is properly configured before calling this
        /// method.</remarks>
        /// <param name="userId">The unique identifier of the user whose scopes are to be retrieved. Must not be <see langword="null"/> or
        /// empty.</param>
        /// <returns>A list of strings representing the IDs of active scopes assigned to the user. The list will be empty if the
        /// user has no active scopes.</returns>
        public static List<string> GetUserScopes(string userId)
        {
            return Db.WithConnection(conn =>
            {
                var scopes = new List<string>();
                using var cmd = conn.CreateCommand();
                cmd.CommandText = """
                    SELECT s.id FROM user_scopes us
                    JOIN scopes s ON us.scope_id = s.id
                    WHERE us.user_id = $uid AND us.is_active = 1 AND s.is_active = 1
                """;
                cmd.Parameters.AddWithValue("$uid", userId);
                using var reader = cmd.ExecuteReader();
                while (reader.Read())
                    scopes.Add(reader.GetString(0));
                return scopes;
            });
        }
    }
}
