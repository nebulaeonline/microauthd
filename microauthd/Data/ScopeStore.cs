using madTypes.Api.Common;
using madTypes.Api.Requests;

using Microsoft.Data.Sqlite;
using Serilog;

namespace microauthd.Data
{
    public static class ScopeStore
    {
        /// <summary>
        /// Creates a new scope in the database and returns the created scope object.
        /// </summary>
        /// <remarks>This method inserts a new scope into the database using the provided <paramref
        /// name="scopeId"/> and the properties of <paramref name="req"/>. If the scope creation fails, the method
        /// returns <see langword="null"/>.</remarks>
        /// <param name="scopeId">The unique identifier for the scope to be created. This value must not be null or empty.</param>
        /// <param name="req">An object containing the details of the scope to be created, including its name and description.</param>
        /// <returns>A <see cref="ScopeObject"/> representing the newly created scope if the operation succeeds; otherwise, <see
        /// langword="null"/>.</returns>
        public static ScopeObject? CreateScope(string scopeId, ScopeObject req)
        {
            var created = Db.WithConnection(conn =>
            {
                using var cmd = conn.CreateCommand();
                cmd.CommandText = """
                    INSERT INTO scopes (id, name, description, created_at, is_active)
                    VALUES ($id, $name, $desc, datetime('now'), 1);
                """;
                cmd.Parameters.AddWithValue("$id", scopeId);
                cmd.Parameters.AddWithValue("$name", req.Name.Trim());
                cmd.Parameters.AddWithValue("$desc", req.Description.Trim() ?? "");

                try
                {
                    return cmd.ExecuteNonQuery() == 1;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Exception while adding scope: {ex.Message}");
                    return false;
                }
            });

            if (!created)
                return null;

            return GetScopeById(scopeId);
        }

        /// <summary>
        /// Determines whether a scope name exists in the database, excluding the specified scope ID.
        /// </summary>
        /// <remarks>This method queries the database to check for the existence of a scope name while
        /// excluding a specific scope ID. It is useful for validating uniqueness of scope names within the
        /// database.</remarks>
        /// <param name="scopeId">The unique identifier of the scope to exclude from the search.</param>
        /// <param name="name">The name of the scope to check for existence.</param>
        /// <returns><see langword="true"/> if a scope with the specified name exists and does not match the provided scope ID;
        /// otherwise, <see langword="false"/>.</returns>
        public static bool DoesScopeNameExist(string scopeId, string name)
        {
            return Db.WithConnection(conn =>
            {
                using var cmd = conn.CreateCommand();
                cmd.CommandText = """
                    SELECT COUNT(*) FROM scopes
                    WHERE name = $name AND id != $id;
                """;
                cmd.Parameters.AddWithValue("$name", name.Trim());
                cmd.Parameters.AddWithValue("$id", scopeId);
                return Convert.ToInt32(cmd.ExecuteScalar()) > 0;
            });
        }

        /// <summary>
        /// Updates the scope identified by the specified <paramref name="scopeId"/> with the provided details.
        /// </summary>
        /// <remarks>This method updates the scope's name, description, and modification timestamp in the
        /// database. If the scope does not exist or the update fails, the method returns <see
        /// langword="null"/>.</remarks>
        /// <param name="scopeId">The unique identifier of the scope to update. Cannot be null or empty.</param>
        /// <param name="updated">An object containing the updated scope details. The <see cref="ScopeObject.Name"/> property must not be null
        /// or empty.</param>
        /// <returns>The updated <see cref="ScopeObject"/> if the operation succeeds; otherwise, <see langword="null"/>.</returns>
        public static ScopeObject? UpdateScope(string scopeId, ScopeObject updated)
        {
            var success = Db.WithConnection(conn =>
            {
                using var cmd = conn.CreateCommand();
                cmd.CommandText = """
                    UPDATE scopes
                    SET name = $name,
                        description = $desc,
                        modified_at = datetime('now')
                    WHERE id = $id;
                """;
                cmd.Parameters.AddWithValue("$name", updated.Name.Trim());
                cmd.Parameters.AddWithValue("$desc", updated.Description?.Trim() ?? "");
                cmd.Parameters.AddWithValue("$id", scopeId);
                return cmd.ExecuteNonQuery() == 1;
            });

            if (!success)
                return null;

            return GetScopeById(scopeId);
        }

        /// <summary>
        /// Retrieves a list of all active scopes from the database.
        /// </summary>
        /// <remarks>This method queries the database for scopes that are marked as active and returns
        /// them in ascending order by name. Each scope is represented as a <see cref="ScopeObject"/>.</remarks>
        /// <returns>A list of <see cref="ScopeObject"/> instances representing all active scopes. If no active scopes are found,
        /// the returned list will be empty.</returns>
        public static List<ScopeObject> ListAllScopes()
        {
            return Db.WithConnection(conn =>
            {
                using var cmd = conn.CreateCommand();
                cmd.CommandText = """
                    SELECT id, name, description, created_at, is_active
                    FROM scopes
                    WHERE is_active = 1
                    ORDER BY name ASC;
                """;

                using var reader = cmd.ExecuteReader();
                var list = new List<ScopeObject>();

                while (reader.Read())
                {
                    list.Add(new ScopeObject
                    {
                        Id = reader.GetString(0),
                        Name = reader.GetString(1).Trim(),
                        Description = reader.IsDBNull(2) ? null : reader.GetString(2).Trim(),
                        CreatedAt = reader.GetDateTime(3).ToUniversalTime(),
                        IsActive = reader.GetInt64(4) == 1
                    });
                }

                return list;
            });
        }

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
                    scopes.Add(reader.GetString(0).Trim());
                return scopes;
            });
        }

        /// <summary>
        /// Retrieves a list of active scope objects associated with the specified user.
        /// </summary>
        /// <remarks>This method queries the database to retrieve scope objects that are both active and
        /// associated with the specified user. The scopes are filtered based on their active status in both the
        /// user-scopes mapping and the scopes table.</remarks>
        /// <param name="userId">The unique identifier of the user whose scope objects are to be retrieved. Must not be <see
        /// langword="null"/> or empty.</param>
        /// <returns>A list of <see cref="ScopeObject"/> instances representing the active scopes associated with the user.
        /// Returns an empty list if no active scopes are found.</returns>
        public static List<ScopeObject> GetUserScopeObjs(string userId)
        {
            return Db.WithConnection(conn =>
            {
                using var cmd = conn.CreateCommand();
                cmd.CommandText = """
                    SELECT s.id, s.name, s.description
                    FROM user_scopes us
                    JOIN scopes s ON us.scope_id = s.id
                    WHERE us.user_id = $uid AND us.is_active = 1 AND s.is_active = 1;
                """;
                cmd.Parameters.AddWithValue("$uid", userId);

                using var reader = cmd.ExecuteReader();
                var list = new List<ScopeObject>();
                while (reader.Read())
                {
                    list.Add(new ScopeObject
                    {
                        Id = reader.GetString(0),
                        Name = reader.GetString(1).Trim(),
                        Description = reader.IsDBNull(2) ? "" : reader.GetString(2).Trim()
                    });
                }

                return list;
            });
        }

        /// <summary>
        /// Assigns distinct, active scopes to a user based on the provided scope IDs.
        /// </summary>
        /// <remarks>This method ensures that only active scopes are assigned to the user. Duplicate scope
        /// IDs in the request are ignored. Scopes that are inactive or do not exist in the database are
        /// skipped.</remarks>
        /// <param name="userId">The unique identifier of the user to whom the scopes will be assigned. Cannot be null or empty.</param>
        /// <param name="req">An object containing the list of scope IDs to assign. The <see cref="AssignScopesRequest.ScopeIds"/>
        /// property must not be null.</param>
        /// <returns>The number of scopes successfully assigned to the user. Returns 0 if no scopes were assigned.</returns>
        public static int AddScopesToUser(string userId, AssignScopesRequest req)
        {
            return Db.WithConnection(conn =>
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
        }

        /// <summary>
        /// Deactivates a scope for a specified user by marking it as inactive.
        /// </summary>
        /// <remarks>This method checks if the specified scope is active before attempting to deactivate
        /// it. If the scope is not active or does not exist, no changes are made, and the method returns 0.</remarks>
        /// <param name="userId">The unique identifier of the user whose scope is to be deactivated. Cannot be null or empty.</param>
        /// <param name="scopeId">The unique identifier of the scope to be deactivated. Cannot be null or empty.</param>
        /// <returns>The number of rows affected by the operation. Returns 0 if the scope is not active or does not exist.</returns>
        public static int RemoveScopeFromUser(string userId, string scopeId)
        {
            return Db.WithConnection(conn =>
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
        }

        /// <summary>
        /// Retrieves a list of active scopes associated with the specified client.
        /// </summary>
        /// <remarks>This method queries the database to retrieve scopes that are both active and
        /// associated with the specified client. The returned scopes include details such as their ID, name,
        /// description, creation date, and active status.</remarks>
        /// <param name="clientId">The unique identifier of the client for which to retrieve scopes. Must not be null or empty.</param>
        /// <returns>A list of <see cref="ScopeObject"/> instances representing the active scopes associated with the specified
        /// client. Returns an empty list if no active scopes are found.</returns>
        public static List<ScopeObject> GetScopesForClient(string clientId)
        {
            return Db.WithConnection(conn =>
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
                var list = new List<ScopeObject>();

                while (reader.Read())
                {
                    list.Add(new ScopeObject
                    {
                        Id = reader.GetString(0),
                        Name = reader.GetString(1).Trim(),
                        Description = reader.IsDBNull(2) ? null : reader.GetString(2).Trim(),
                        CreatedAt = reader.GetDateTime(3).ToUniversalTime(),
                        IsActive = reader.GetInt64(4) == 1
                    });
                }

                return list;
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
                        Name = reader.GetString(1).Trim()
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
                        Name = reader.GetString(1).Trim()
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
                        Name = reader.GetString(1).Trim()
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
                        Name = reader.GetString(1).Trim(),
                        Description = reader.IsDBNull(2) ? null : reader.GetString(2).Trim(),
                        IsProtected = reader.GetBoolean(3),
                        CreatedAt = reader.GetDateTime(4).ToUniversalTime()
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
                        Name = reader.GetString(1).Trim(),
                        Description = reader.IsDBNull(2) ? null : reader.GetString(2).Trim(),
                        IsProtected = reader.GetBoolean(3),
                        CreatedAt = reader.GetDateTime(4).ToUniversalTime()
                    };
                }
                return null;
            });
        }

        /// <summary>
        /// Retrieves the unique identifier (ID) of a scope based on its name.
        /// </summary>
        /// <remarks>This method queries the database to find the ID of the scope associated with the
        /// given name. If multiple scopes share the same name, only the first match is returned.</remarks>
        /// <param name="name">The name of the scope to search for. Cannot be null or empty.</param>
        /// <returns>The unique identifier of the scope as a string, or <see langword="null"/> if no scope with the specified
        /// name exists.</returns>
        public static string? GetScopeIdByName(string name)
        {
            return Db.WithConnection(conn =>
            {
                using var cmd = conn.CreateCommand();
                cmd.CommandText = "SELECT id FROM scopes WHERE name = $name LIMIT 1;";
                cmd.Parameters.AddWithValue("$name", name.Trim());

                var result = cmd.ExecuteScalar();
                return result == null ? null : Convert.ToString(result);
            });
        }

        /// <summary>
        /// Assigns distinct, active scopes to a client and returns the number of scopes successfully added.
        /// </summary>
        /// <remarks>Only scopes that are active and exist in the database will be assigned to the client.
        /// Duplicate scope IDs in the request are ignored. If a scope is already assigned to the client, it will not be
        /// reassigned.</remarks>
        /// <param name="clientId">The unique identifier of the client to which the scopes will be assigned. Cannot be null or empty.</param>
        /// <param name="req">An <see cref="AssignScopesRequest"/> object containing the list of scope IDs to assign. The list may include
        /// duplicates, which will be ignored.</param>
        /// <returns>The number of scopes successfully assigned to the client. Returns 0 if no scopes were added.</returns>
        public static int AddScopesToClient(string clientId, AssignScopesRequest req)
        {
            return Db.WithConnection(conn =>
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
        }
        /// <summary>
        /// Deletes a scope with the specified ID if it is not protected.
        /// </summary>
        /// <remarks> This method deletes a scope from the database only if the scope is not marked as
        /// protected. Protected scopes cannot be deleted. Ensure the provided <paramref name="scopeId"/> corresponds to
        /// a valid, non-protected scope. </remarks>
        /// <param name="scopeId">The unique identifier of the scope to delete. Cannot be null or empty.</param>
        /// <returns><see langword="true"/> if the scope was successfully deleted; otherwise, <see langword="false"/>. </returns>
        public static bool DeleteScope(string scopeId)
        {
            return Db.WithConnection(conn =>
            {
                using var cmd = conn.CreateCommand();
                cmd.CommandText = "DELETE FROM scopes WHERE id = $id AND is_protected = 0;";
                cmd.Parameters.AddWithValue("$id", scopeId);

                return cmd.ExecuteNonQuery() > 0;                
            });
        }

        /// <summary>
        /// Removes a specified scope from a client in the database.
        /// </summary>
        /// <remarks>This method executes a database operation to remove the association between a client
        /// and a scope. Ensure that the provided identifiers correspond to valid entries in the database.</remarks>
        /// <param name="clientId">The unique identifier of the client from which the scope will be removed. Cannot be null or empty.</param>
        /// <param name="scopeId">The unique identifier of the scope to be removed. Cannot be null or empty.</param>
        /// <returns>The number of rows affected by the operation. Returns 0 if no matching client-scope pair was found.</returns>
        public static int RemoveScopeFromClient(string clientId, string scopeId)
        {
            return Db.WithConnection(conn =>
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
