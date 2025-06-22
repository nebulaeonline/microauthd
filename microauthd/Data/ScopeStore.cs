using madTypes.Api.Common;

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

        /// <summary>
        /// Retrieves the list of active scopes assigned to a specific user.
        /// </summary>
        /// <remarks>This method queries the database to retrieve scopes that are both active and assigned
        /// to the specified user. The returned scopes are filtered to include only those marked as active in both the
        /// user-scopes mapping and the scopes table.</remarks>
        /// <param name="userId">The unique identifier of the user whose assigned scopes are to be retrieved. Must not be <see
        /// langword="null"/> or empty.</param>
        /// <returns>A list of <see cref="ScopeDto"/> objects representing the active scopes assigned to the user. Returns an
        /// empty list if the user has no active scopes.</returns>
        public static List<ScopeDto> GetAssignedScopesForUser(string userId)
        {
            return Db.WithConnection(conn =>
            {
                var scopes = new List<ScopeDto>();
                using var cmd = conn.CreateCommand();
                cmd.CommandText = """
                    SELECT s.id, s.name FROM user_scopes us
                    JOIN scopes s ON us.scope_id = s.id
                    WHERE us.user_id = $uid AND us.is_active = 1 AND s.is_active = 1
                """;
                cmd.Parameters.AddWithValue("$uid", userId);
                using var reader = cmd.ExecuteReader();
                while (reader.Read())
                {
                    scopes.Add(new ScopeDto
                    {
                        Id = reader.GetString(0),
                        Name = reader.GetString(1)
                    });
                }
                return scopes;
            });
        }

        /// <summary>
        /// Retrieves the list of active scopes assigned to a specified client.
        /// </summary>
        /// <remarks>This method queries the database to retrieve scopes that are both active and assigned
        /// to the specified client. Ensure the client ID provided corresponds to a valid client in the
        /// system.</remarks>
        /// <param name="clientId">The unique identifier of the client for which to retrieve assigned scopes. Must not be null or empty.</param>
        /// <returns>A list of <see cref="ScopeDto"/> objects representing the active scopes assigned to the client. Returns an
        /// empty list if no active scopes are assigned.</returns>
        public static List<ScopeDto> GetAssignedScopesForClient(string clientId)
        {
            return Db.WithConnection(conn =>
            {
                var scopes = new List<ScopeDto>();
                using var cmd = conn.CreateCommand();
                cmd.CommandText = """
                    SELECT s.id, s.name FROM client_scopes cs
                    JOIN scopes s ON cs.scope_id = s.id
                    WHERE cs.client_id = $cid AND cs.is_active = 1 AND s.is_active = 1
                """;
                cmd.Parameters.AddWithValue("$cid", clientId);
                using var reader = cmd.ExecuteReader();
                while (reader.Read())
                {
                    scopes.Add(new ScopeDto
                    {
                        Id = reader.GetString(0),
                        Name = reader.GetString(1)
                    });
                }
                return scopes;
            });
        }

        /// <summary>
        /// Retrieves a list of all active scopes from the database.
        /// </summary>
        /// <remarks>This method queries the database for scopes that are marked as active and returns
        /// them as a list of <see cref="ScopeDto"/> objects. Each scope includes its unique identifier and
        /// name.</remarks>
        /// <returns>A list of <see cref="ScopeDto"/> objects representing all active scopes. If no active scopes are found, the
        /// list will be empty.</returns>
        public static List<ScopeDto> GetAllScopeDtos()
        {
            return Db.WithConnection(conn =>
            {
                var scopes = new List<ScopeDto>();
                using var cmd = conn.CreateCommand();
                cmd.CommandText = "SELECT id, name FROM scopes WHERE is_active = 1;";
                using var reader = cmd.ExecuteReader();
                while (reader.Read())
                {
                    scopes.Add(new ScopeDto
                    {
                        Id = reader.GetString(0),
                        Name = reader.GetString(1)
                    });
                }
                return scopes;
            });
        }

        /// <summary>
        /// Retrieves a paginated list of active scopes from the database.
        /// </summary>
        /// <remarks>Scopes are ordered alphabetically by their name. Only scopes marked as active are
        /// included in the results.</remarks>
        /// <param name="offset">The zero-based index of the first scope to retrieve. Must be non-negative.</param>
        /// <param name="limit">The maximum number of scopes to retrieve. Must be greater than zero.</param>
        /// <returns>A list of <see cref="ScopeObject"/> instances representing the active scopes. The list will be empty if no
        /// active scopes are found within the specified range.</returns>
        public static List<ScopeObject> ListScopes(int offset = 0, int limit = 50)
        {
            return Db.WithConnection(conn =>
            {
                using var cmd = conn.CreateCommand();
                cmd.CommandText = """
                    SELECT id, name, description, is_protected, created_at
                    FROM scopes
                    WHERE is_active = 1
                    ORDER BY name
                    LIMIT $limit OFFSET $offset
                """;
                cmd.Parameters.AddWithValue("$limit", limit);
                cmd.Parameters.AddWithValue("$offset", offset);

                using var reader = cmd.ExecuteReader();
                var results = new List<ScopeObject>();
                while (reader.Read())
                {
                    results.Add(new ScopeObject
                    {
                        Id = reader.GetString(0),
                        Name = reader.GetString(1),
                        Description = reader.IsDBNull(2) ? null : reader.GetString(2),
                        IsProtected = reader.GetBoolean(3),
                        CreatedAt = reader.GetDateTime(4)
                    });
                }
                return results;
            });
        }

        /// <summary>
        /// Retrieves an active scope object by its unique identifier.
        /// </summary>
        /// <remarks>This method queries the database for a scope with the specified identifier that is
        /// marked as active. If the <paramref name="scopeId"/> is invalid (null, empty, or whitespace), the method
        /// returns <see langword="null"/>.</remarks>
        /// <param name="scopeId">The unique identifier of the scope to retrieve. This value cannot be null, empty, or consist solely of
        /// whitespace.</param>
        /// <returns>A <see cref="ScopeObject"/> representing the active scope with the specified identifier, or <see
        /// langword="null"/> if no matching active scope is found.</returns>
        public static ScopeObject? GetScopeById(string scopeId)
        {
            if (string.IsNullOrWhiteSpace(scopeId))
                return null;

            return Db.WithConnection(conn =>
            {
                using var cmd = conn.CreateCommand();
                cmd.CommandText = """
                    SELECT id, name, description, is_protected, created_at
                    FROM scopes
                    WHERE id = $scopeId AND is_active = 1
                """;
                cmd.Parameters.AddWithValue("$scopeId", scopeId);
                using var reader = cmd.ExecuteReader();
                if (reader.Read())
                {
                    return new ScopeObject
                    {
                        Id = reader.GetString(0),
                        Name = reader.GetString(1),
                        Description = reader.IsDBNull(2) ? null : reader.GetString(2),
                        IsProtected = reader.GetBoolean(3),
                        CreatedAt = reader.GetDateTime(4)
                    };
                }
                return null;
            });
        }

        /// <summary>
        /// Retrieves the count of active scopes from the database.
        /// </summary>
        /// <remarks>This method executes a database query to count the rows in the "scopes" table where
        /// the "is_active" column is set to 1. Ensure that the database connection is properly configured before
        /// calling this method.</remarks>
        /// <returns>The total number of active scopes. Returns 0 if no active scopes are found.</returns>
        public static int GetScopeCount()
        {
            return Db.WithConnection(conn =>
            {
                using var cmd = conn.CreateCommand();
                cmd.CommandText = "SELECT COUNT(*) FROM scopes WHERE is_active = 1;";
                return Convert.ToInt32(cmd.ExecuteScalar());
            });
        }
    }
}
