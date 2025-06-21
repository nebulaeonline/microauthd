using madTypes.Api.Common;
using madTypes.Api.Requests;
using madTypes.Api.Responses;
using madTypes.Common;
using microauthd.Common;
using microauthd.Config;
using microauthd.Data;
using Microsoft.Data.Sqlite;
using Serilog;

namespace microauthd.Services;

public static class ScopeService
{
    /// <summary>
    /// Creates a new scope with the specified name and description.
    /// </summary>
    /// <remarks>This method validates the scope name before attempting to create the scope. If the name is
    /// invalid, the operation fails immediately. If a scope with the same name already exists, the operation fails and
    /// returns an appropriate error message. The method also logs the operation for auditing purposes if the optional
    /// auditing parameters are provided.</remarks>
    /// <param name="req">The request containing the name and description of the scope to create. The <see cref="ScopeObject.Name"/>
    /// must be non-empty, alphanumeric, and may include hyphens or underscores.</param>
    /// <param name="actorUserId">The optional ID of the user performing the operation, used for auditing purposes.</param>
    /// <param name="ip">The optional IP address of the user performing the operation, used for auditing purposes.</param>
    /// <param name="ua">The optional user agent string of the user performing the operation, used for auditing purposes.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/>.  If the operation succeeds, the result
    /// indicates success and includes a message confirming the creation of the scope.  If the operation fails, the
    /// result indicates failure and includes an error message.</returns>
    public static ApiResult<ScopeObject> CreateScope(
        ScopeObject req,
        AppConfig config,
        string? actorUserId = null,
        string? ip = null,
        string? ua = null)
    {
        if (!Utils.IsValidTokenName(req.Name))
            return ApiResult<ScopeObject>.Fail("Invalid scope name: must be non-empty, and cannot contain whitespace.");

        var scopeId = Guid.NewGuid().ToString();

        var created = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
            INSERT INTO scopes (id, name, description, created_at, is_active)
            VALUES ($id, $name, $desc, datetime('now'), 1);
        """;
            cmd.Parameters.AddWithValue("$id", scopeId);
            cmd.Parameters.AddWithValue("$name", req.Name);
            cmd.Parameters.AddWithValue("$desc", req.Description ?? "");

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
            return ApiResult<ScopeObject>.Fail("Scope creation failed (duplicate name?)");

        AuditLogger.AuditLog(config, actorUserId, "create_scope", req.Name, ip, ua);

        var scope = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
            SELECT id, name, description FROM scopes WHERE id = $id;
        """;
            cmd.Parameters.AddWithValue("$id", scopeId);

            using var reader = cmd.ExecuteReader();
            if (!reader.Read())
                return null;

            return new ScopeObject
            {
                Id = reader.GetString(0),
                Name = reader.GetString(1),
                Description = reader.GetString(2)
            };
        });

        if (scope is null)
            return ApiResult<ScopeObject>.Fail("Created scope could not be reloaded.");

        return ApiResult<ScopeObject>.Ok(scope);
    }

    /// <summary>
    /// Updates an existing scope with the specified details.
    /// </summary>
    /// <remarks>The method performs validation on the provided scope details, ensuring the name is valid and
    /// does not conflict with existing scopes. If the update is successful, the updated scope is retrieved and
    /// returned. If the update fails or the scope cannot be retrieved, an error result is returned.</remarks>
    /// <param name="id">The unique identifier of the scope to update.</param>
    /// <param name="updated">The updated scope details. The <see cref="ScopeObject.Name"/> property must be a valid token identifier and
    /// cannot be null or whitespace.</param>
    /// <param name="config">The application configuration used for the operation.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing the updated <see cref="ScopeObject"/> if the operation succeeds;
    /// otherwise, an <see cref="ApiResult{T}"/> with an error message describing the failure.</returns>
    public static ApiResult<ScopeObject> UpdateScope(
        string id,
        ScopeObject updated,
        AppConfig config
    )
    {
        if (string.IsNullOrWhiteSpace(updated.Name))
            return ApiResult<ScopeObject>.Fail("Scope name is required.");

        if (!Utils.IsValidTokenName(updated.Name))
            return ApiResult<ScopeObject>.Fail("Scope name must be a valid token identifier.");

        // Check for name collision
        var conflict = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
            SELECT COUNT(*) FROM scopes
            WHERE name = $name AND id != $id;
        """;
            cmd.Parameters.AddWithValue("$name", updated.Name);
            cmd.Parameters.AddWithValue("$id", id);
            return Convert.ToInt32(cmd.ExecuteScalar()) > 0;
        });

        if (conflict)
            return ApiResult<ScopeObject>.Fail("Another scope already uses that name.");

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
            cmd.Parameters.AddWithValue("$name", updated.Name);
            cmd.Parameters.AddWithValue("$desc", updated.Description ?? "");
            cmd.Parameters.AddWithValue("$id", id);
            return cmd.ExecuteNonQuery() == 1;
        });

        if (!success)
            return ApiResult<ScopeObject>.Fail("Scope update failed or not found.");

        // Re-fetch and return updated
        var scope = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
            SELECT id, name, description, created_at, is_active
            FROM scopes
            WHERE id = $id;
        """;
            cmd.Parameters.AddWithValue("$id", id);

            using var reader = cmd.ExecuteReader();
            if (!reader.Read())
                return null;

            return new ScopeObject
            {
                Id = reader.GetString(0),
                Name = reader.GetString(1),
                Description = reader.GetString(2),
                CreatedAt = reader.GetString(3),
                IsActive = reader.GetBoolean(4)
            };
        });

        return scope is not null
            ? ApiResult<ScopeObject>.Ok(scope)
            : ApiResult<ScopeObject>.Fail("Updated scope could not be retrieved.");
    }

    /// <summary>
    /// Retrieves a list of all active scopes from the database.
    /// </summary>
    /// <remarks>This method queries the database for all scopes that are marked as active and returns them in
    /// ascending order by name. Each scope includes its ID, name, description, creation date, and active
    /// status.</remarks>
    /// <returns>An <see cref="ApiResult{T}"/> containing a list of <see cref="ScopeObject"/> objects representing the active
    /// scopes. If no active scopes are found, the list will be empty.</returns>
    public static ApiResult<List<ScopeObject>> ListAllScopes()
    {
        var scopes = Db.WithConnection(conn =>
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
                    Name = reader.GetString(1),
                    Description = reader.IsDBNull(2) ? null : reader.GetString(2),
                    CreatedAt = reader.GetString(3),
                    IsActive = reader.GetInt64(4) == 1
                });
            }

            return list;
        });

        return ApiResult<List<ScopeObject>>.Ok(scopes);
    }

    /// <summary>
    /// Retrieves a scope object by its unique identifier.
    /// </summary>
    /// <remarks>This method queries the database for a scope with the specified identifier. If no matching
    /// scope  is found, the result will indicate a "Not Found" status. The returned <see cref="ScopeObject"/>  includes
    /// the scope's ID, name, and description.</remarks>
    /// <param name="id">The unique identifier of the scope to retrieve. Cannot be null or empty.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing the <see cref="ScopeObject"/> if found;  otherwise, an <see
    /// cref="ApiResult{T}"/> indicating that the scope was not found.</returns>
    public static ApiResult<ScopeObject> GetScopeById(string id)
    {
        var scope = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
        SELECT id, name, description
        FROM scopes
        WHERE id = $id
    """;
            cmd.Parameters.AddWithValue("$id", id);

            using var reader = cmd.ExecuteReader();
            if (!reader.Read())
                return null;

            return new ScopeObject
            {
                Id = reader.GetString(0),
                Name = reader.GetString(1),
                Description = reader.GetString(2)
            };
        });

        return scope is null
            ? ApiResult<ScopeObject>.NotFound($"Scope '{id}' not found.")
            : ApiResult<ScopeObject>.Ok(scope);
    }

    /// <summary>
    /// Deletes a scope identified by the specified scope ID from the database.
    /// </summary>
    /// <remarks>This method attempts to delete the specified scope from the database. If the deletion fails, 
    /// an error is logged, and a failure result is returned. If the deletion succeeds, an audit log  entry is created
    /// to record the operation.</remarks>
    /// <param name="scopeId">The unique identifier of the scope to delete. Cannot be null or empty.</param>
    /// <param name="config">The application configuration used for logging and auditing. Cannot be null.</param>
    /// <param name="actorUserId">The ID of the user performing the operation, used for auditing. Optional.</param>
    /// <param name="ip">The IP address of the user performing the operation, used for auditing. Optional.</param>
    /// <param name="ua">The user agent of the user performing the operation, used for auditing. Optional.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/> that indicates the result of the
    /// operation. Returns a success result if the scope was deleted successfully; otherwise, returns a failure result
    /// with an error message.</returns>
    public static ApiResult<MessageResponse> DeleteScope(
        string scopeId,
        AppConfig config,
        string? actorUserId = null,
        string? ip = null,
        string? ua = null)
    {
        var deleted = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "DELETE FROM scopes WHERE id = $id AND is_protected = 0;";
            cmd.Parameters.AddWithValue("$id", scopeId);

            try
            {
                return cmd.ExecuteNonQuery() > 0;
            }
            catch (SqliteException ex)
            {
                Log.Error(ex, "Failed to delete scope {ScopeId}", scopeId);
                return false;
            }
        });

        if (!deleted)
            return ApiResult<MessageResponse>.Fail("Failed to delete scope");

        AuditLogger.AuditLog(config, actorUserId, "delete_scope", scopeId, ip, ua);
        return ApiResult<MessageResponse>.Ok(new(true, $"Scope '{scopeId}' deleted"));
    }

    /// <summary>
    /// Assigns one or more scopes to a client, ensuring that the scopes are active and valid.
    /// </summary>
    /// <remarks>This method ensures that only active and valid scopes are assigned to the client. Duplicate
    /// or invalid scope IDs are ignored. If no valid scopes are assigned, the method returns a failure result.  The
    /// operation is logged for auditing purposes if <paramref name="actorUserId"/>, <paramref name="ip"/>, or <paramref
    /// name="ua"/> is provided.</remarks>
    /// <param name="clientId">The unique identifier of the client to which the scopes will be assigned. Cannot be null, empty, or whitespace.</param>
    /// <param name="req">The request containing the list of scope IDs to assign. Must include at least one valid scope ID.</param>
    /// <param name="actorUserId">The optional identifier of the user performing the operation, used for auditing purposes.</param>
    /// <param name="ip">The optional IP address of the user performing the operation, used for auditing purposes.</param>
    /// <param name="ua">The optional user agent string of the user performing the operation, used for auditing purposes.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/> that indicates the result of the
    /// operation. Returns a success result if at least one scope was successfully assigned to the client. Returns a
    /// failure result if no scopes were assigned or if the input parameters are invalid.</returns>
    public static ApiResult<MessageResponse> AddScopesToClient(
        string clientId,
        AssignScopesRequest req,
        AppConfig config,
        string? actorUserId = null,
        string? ip = null,
        string? ua = null)
    {
        if (string.IsNullOrWhiteSpace(clientId))
            return ApiResult<MessageResponse>.Fail("Client ID is required");

        if (req.ScopeIds is null || req.ScopeIds.Count == 0)
            return ApiResult<MessageResponse>.Fail("At least one scope ID is required");

        int added = Db.WithConnection(conn =>
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

        if (added == 0)
            return ApiResult<MessageResponse>.Fail("No scopes were assigned. Check scope IDs or duplicates.");

        AuditLogger.AuditLog(config, actorUserId, "assign_scope_to_client", clientId, ip, ua);

        return ApiResult<MessageResponse>.Ok(new(true, $"Assigned {added} scope(s) to client."));
    }

    /// <summary>
    /// Retrieves the list of active scopes associated with a specified client.
    /// </summary>
    /// <remarks>This method queries the database to retrieve the active scopes linked to the
    /// specified client.  Only scopes, clients, and client-scope relationships marked as active are included in the
    /// result.</remarks>
    /// <param name="clientId">The unique identifier of the client for which to retrieve the associated scopes.  This value cannot be null
    /// or empty.</param>
    /// <returns>A list of strings representing the names of the active scopes associated with the specified client.  The
    /// list will be empty if no active scopes are found.</returns>
    public static List<string> ListScopesForClient(string clientId)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT s.name
                    FROM user_scopes us
                    JOIN scopes s ON us.scope_id = s.id
                    WHERE us.user_id = $uid
                      AND us.is_active = 1
                      AND s.is_active = 1
                      AND s.name IS NOT NULL;
            """;
            cmd.Parameters.AddWithValue("$cid", clientId);

            using var reader = cmd.ExecuteReader();
            var scopes = new List<string>();
            while (reader.Read())
                scopes.Add(reader.GetString(0));

            return scopes;
        });
    }

    /// <summary>
    /// Retrieves the list of active scopes associated with a specified client.
    /// </summary>
    /// <remarks>This method queries the database to retrieve scopes that are both active and associated with
    /// the specified client. The returned scopes include details such as the scope's ID, name, description, creation
    /// date, and active status.</remarks>
    /// <param name="clientId">The unique identifier of the client for which to retrieve scopes. Cannot be null, empty, or whitespace.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a list of <see cref="ScopeObject"/> objects representing the active
    /// scopes for the client. If the <paramref name="clientId"/> is invalid, the result will indicate failure with an
    /// appropriate error message.</returns>
    public static ApiResult<List<ScopeObject>> GetScopesForClient(string clientId)
    {
        if (string.IsNullOrWhiteSpace(clientId))
            return ApiResult<List<ScopeObject>>.Fail("Client ID is required");

        var scopes = Db.WithConnection(conn =>
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
                    Name = reader.GetString(1),
                    Description = reader.IsDBNull(2) ? null : reader.GetString(2),
                    CreatedAt = reader.GetString(3),
                    IsActive = reader.GetInt64(4) == 1
                });
            }

            return list;
        });

        return ApiResult<List<ScopeObject>>.Ok(scopes);
    }


    /// <summary>
    /// Removes a specified scope from a client.
    /// </summary>
    /// <param name="clientId">The unique identifier of the client from which the scope will be removed. Cannot be null or whitespace.</param>
    /// <param name="scopeId">The unique identifier of the scope to be removed. Cannot be null or whitespace.</param>
    /// <param name="actorUserId">The optional identifier of the user performing the operation, used for auditing purposes.</param>
    /// <param name="ip">The optional IP address of the user performing the operation, used for auditing purposes.</param>
    /// <param name="ua">The optional user agent string of the user performing the operation, used for auditing purposes.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/> that indicates the result of the
    /// operation. Returns a success result if the scope was successfully removed, or a failure result if the scope was
    /// not assigned or already removed.</returns>
    public static ApiResult<MessageResponse> RemoveScopeFromClient(
        string clientId,
        string scopeId,
        AppConfig config,
        string? actorUserId = null,
        string? ip = null,
        string? ua = null)
    {
        if (string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(scopeId))
            return ApiResult<MessageResponse>.Fail("Client ID and Scope ID are required");

        var affected = Db.WithConnection(conn =>
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

        if (affected == 0)
            return ApiResult<MessageResponse>.Fail("Scope not assigned or already removed");

        AuditLogger.AuditLog(config, actorUserId, "remove_scope_from_client", $"{clientId}:{scopeId}", ip, ua);

        return ApiResult<MessageResponse>.Ok(new(true, $"Removed scope '{scopeId}' from client '{clientId}'"));
    }


    /// <summary>
    /// Retrieves a list of active scopes assigned to a specified user.
    /// </summary>
    /// <remarks>A scope represents a specific permission or access level assigned to a user.  This method
    /// queries the database for active scopes associated with the user and filters out inactive scopes.</remarks>
    /// <param name="userId">The unique identifier of the user whose scopes are to be retrieved. Cannot be null, empty, or whitespace.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a list of scope names assigned to the user.  If the user has no active
    /// scopes, the list will be empty.  Returns a failure result if the <paramref name="userId"/> is invalid.</returns>
    public static ApiResult<List<ScopeObject>> ListScopesForUser(string userId)
    {
        if (string.IsNullOrWhiteSpace(userId))
            return ApiResult<List<ScopeObject>>.Fail("User ID is required");

        var scopes = Db.WithConnection(conn =>
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
                    Name = reader.GetString(1),
                    Description = reader.IsDBNull(2) ? "" : reader.GetString(2)
                });
            }

            return list;
        });

        return ApiResult<List<ScopeObject>>.Ok(scopes);
    }

    /// <summary>
    /// Assigns one or more scopes to a user, ensuring that the scopes are active and not already assigned.
    /// </summary>
    /// <remarks>This method ensures that only active scopes are assigned to the user. If a scope is already
    /// assigned or does not exist, it will be ignored. The operation is logged for auditing purposes if <paramref
    /// name="actorUserId"/> is provided.</remarks>
    /// <param name="userId">The unique identifier of the user to whom the scopes will be assigned. Cannot be null, empty, or whitespace.</param>
    /// <param name="req">An object containing the list of scope IDs to assign. Must include at least one scope ID.</param>
    /// <param name="actorUserId">The unique identifier of the user performing the operation. Optional.</param>
    /// <param name="ip">The IP address of the actor performing the operation. Optional.</param>
    /// <param name="ua">The user agent string of the actor performing the operation. Optional.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/> that indicates the result of the
    /// operation. Returns a success message if at least one scope was assigned, or an error message if no scopes were
    /// assigned.</returns>
    public static ApiResult<MessageResponse> AddScopesToUser(
        string userId,
        AssignScopesRequest req,
        AppConfig config,
        string? actorUserId = null,
        string? ip = null,
        string? ua = null)
    {
        if (string.IsNullOrWhiteSpace(userId))
            return ApiResult<MessageResponse>.Fail("User ID is required");

        if (req.ScopeIds.Count == 0)
            return ApiResult<MessageResponse>.Fail("At least one scope ID is required");

        var added = Db.WithConnection(conn =>
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

        if (added == 0)
            return ApiResult<MessageResponse>.Fail("No scopes were assigned — check if they exist or were already assigned");

        AuditLogger.AuditLog(config, actorUserId, "assign_scope_to_user", userId, ip, ua);

        return ApiResult<MessageResponse>.Ok(new(true, $"Assigned {added} scope(s) to user."));
    }

    /// <summary>
    /// Removes a specified scope from a user's active scopes.
    /// </summary>
    /// <remarks>This method deactivates the specified scope for the given user if it is currently active. If
    /// the scope is not assigned to the user or is already inactive, the method returns a failure result. The operation
    /// is logged for auditing purposes if an <paramref name="actorUserId"/> is provided.</remarks>
    /// <param name="userId">The unique identifier of the user from whom the scope will be removed. Cannot be null or whitespace.</param>
    /// <param name="scopeId">The unique identifier of the scope to be removed. Cannot be null or whitespace.</param>
    /// <param name="actorUserId">The unique identifier of the user performing the operation. Optional.</param>
    /// <param name="ip">The IP address of the actor performing the operation. Optional.</param>
    /// <param name="ua">The user agent string of the actor performing the operation. Optional.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/> that indicates the result of the
    /// operation. Returns a success result if the scope was successfully removed, or a failure result with an
    /// appropriate message if the operation could not be completed.</returns>
    public static ApiResult<MessageResponse> RemoveScopeFromUser(
        string userId,
        string scopeId,
        AppConfig config,
        string? actorUserId = null,
        string? ip = null,
        string? ua = null)
    {
        if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(scopeId))
            return ApiResult<MessageResponse>.Fail("User ID and Scope ID are required");

        var affected = Db.WithConnection(conn =>
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

        if (affected == 0)
            return ApiResult<MessageResponse>.Fail("Scope not assigned or already removed");

        AuditLogger.AuditLog(config, actorUserId, "remove_scope_from_user", $"{userId}:{scopeId}", ip, ua);

        return ApiResult<MessageResponse>.Ok(new(true, $"Removed scope '{scopeId}' from user '{userId}'."));
    }

    /// <summary>
    /// Retrieves the total number of scopes currently stored.
    /// </summary>
    /// <returns>The total count of scopes as an integer. Returns 0 if no scopes are stored.</returns>
    public static int GetScopeCount() => ScopeStore.GetScopeCount();
}
