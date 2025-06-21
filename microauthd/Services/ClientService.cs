using madTypes.Api.Common;
using madTypes.Api.Requests;
using madTypes.Api.Responses;
using madTypes.Common;
using microauthd.Common;
using microauthd.Config;
using microauthd.Data;
using Microsoft.Data.Sqlite;
using Serilog;
using System.Text;
using static nebulae.dotArgon2.Argon2;

namespace microauthd.Services;

public static class ClientService
{
    /// <summary>
    /// Attempts to create a new client with the specified request parameters and configuration.
    /// </summary>
    /// <remarks>The method validates the provided client ID and client secret before attempting to create the
    /// client.  If the client creation fails (e.g., due to a duplicate client ID), an error message is
    /// returned.</remarks>
    /// <param name="req">The request containing the client details, including <see cref="CreateClientRequest.ClientId"/> and <see
    /// cref="CreateClientRequest.ClientSecret"/>.</param>
    /// <param name="config">The application configuration used for hashing and other settings.</param>
    /// <param name="actorUserId">The optional ID of the user performing the operation, used for auditing purposes.</param>
    /// <param name="ip">The optional IP address of the user performing the operation, used for auditing purposes.</param>
    /// <param name="ua">The optional user agent string of the user performing the operation, used for auditing purposes.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/>.  If the client is successfully
    /// created, the result is successful and includes a message indicating the created client ID.  Otherwise, the
    /// result is a failure with an appropriate error message.</returns>
    public static ApiResult<ClientObject> TryCreateClient(
        CreateClientRequest req,
        AppConfig config,
        string? actorUserId = null,
        string? ip = null,
        string? ua = null)
    {
        if (!Utils.IsValidTokenName(req.ClientId))
            return ApiResult<ClientObject>.Fail("Invalid client_id");

        if (string.IsNullOrWhiteSpace(req.ClientSecret))
            return ApiResult<ClientObject>.Fail("Client secret required");

        var hash = Argon2HashEncodedToString(
            Argon2Algorithm.Argon2id,
            (uint)config.Argon2Time,
            (uint)config.Argon2Memory,
            (uint)config.Argon2Parallelism,
            Encoding.UTF8.GetBytes(req.ClientSecret),
            Utils.GenerateSalt(config.Argon2SaltLength),
            config.Argon2HashLength
        );

        var clientId = Guid.NewGuid().ToString();

        var insertSuccess = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                INSERT INTO clients (id, client_identifier, client_secret_hash, display_name, audience, created_at, modified_at, is_active)
                VALUES ($id, $cid, $hash, $name, $aud, datetime('now'), datetime('now'), 1);
            """;
            cmd.Parameters.AddWithValue("$id", clientId);
            cmd.Parameters.AddWithValue("$cid", req.ClientId);
            cmd.Parameters.AddWithValue("$hash", hash);
            cmd.Parameters.AddWithValue("$name", req.DisplayName ?? "");
            cmd.Parameters.AddWithValue("$aud", req.Audience ?? "microauthd");

            try
            {
                return cmd.ExecuteNonQuery() == 1;
            }
            catch (SqliteException)
            {
                return false;
            }
        });

        if (!insertSuccess)
            return ApiResult<ClientObject>.Fail("Client creation failed (duplicate client_id?)");

        AuditLogger.AuditLog(config, actorUserId, "create_client", req.ClientId, ip, ua);

        var client = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
            SELECT id, client_identifier, display_name, created_at, is_active
            FROM clients WHERE id = $id;
        """;
            cmd.Parameters.AddWithValue("$id", clientId);
            using var reader = cmd.ExecuteReader();
            if (!reader.Read())
                return null;

            return new ClientObject
            {
                Id = reader.GetString(0),
                ClientId = reader.GetString(1),
                DisplayName = reader.GetString(2),
                CreatedAt = reader.GetString(3),
                IsActive = reader.GetBoolean(4)
            };
        });

        if (client is null)
            return ApiResult<ClientObject>.Fail("Created client could not be reloaded.");

        return ApiResult<ClientObject>.Ok(client);
    }

    /// <summary>
    /// Updates the details of an existing client in the database.
    /// </summary>
    /// <remarks>The method performs several validations, including ensuring that the client identifier is
    /// non-empty, valid, and not already in use by another client. If the update is successful, the method retrieves
    /// and returns the updated client object. If the update fails or the client cannot be found, an error result is
    /// returned.</remarks>
    /// <param name="id">The unique identifier of the client to update.</param>
    /// <param name="updated">An object containing the updated client details. The <see cref="ClientObject.ClientId"/> property must be
    /// non-empty and valid.</param>
    /// <param name="config">The application configuration used for the operation.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing the updated <see cref="ClientObject"/> if the operation succeeds;
    /// otherwise, an <see cref="ApiResult{T}"/> with an error message describing the failure.</returns>
    public static ApiResult<ClientObject> UpdateClient(
        string id,
        ClientObject updated,
        AppConfig config
    )
    {
        if (string.IsNullOrWhiteSpace(updated.ClientId))
            return ApiResult<ClientObject>.Fail("Client identifier is required.");

        if (!Utils.IsValidTokenName(updated.ClientId))
            return ApiResult<ClientObject>.Fail("Client identifier is not valid.");

        // Check for identifier conflicts
        var conflict = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
            SELECT COUNT(*) FROM clients
            WHERE client_identifier = $cid AND id != $id;
        """;
            cmd.Parameters.AddWithValue("$cid", updated.ClientId);
            cmd.Parameters.AddWithValue("$id", id);
            return Convert.ToInt32(cmd.ExecuteScalar()) > 0;
        });

        if (conflict)
            return ApiResult<ClientObject>.Fail("Another client already uses that identifier.");

        var success = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
            UPDATE clients
            SET client_identifier = $cid,
                display_name = $name,
                is_active = $active,
                modified_at = datetime('now')
            WHERE id = $id;
        """;
            cmd.Parameters.AddWithValue("$cid", updated.ClientId);
            cmd.Parameters.AddWithValue("$name", updated.DisplayName ?? "");
            cmd.Parameters.AddWithValue("$active", updated.IsActive ? 1 : 0);
            cmd.Parameters.AddWithValue("$id", id);
            return cmd.ExecuteNonQuery() == 1;
        });

        if (!success)
            return ApiResult<ClientObject>.Fail("Client update failed or client not found.");

        // Reload full object to return
        var client = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
            SELECT id, client_identifier, display_name, is_active, created_at
            FROM clients
            WHERE id = $id;
        """;
            cmd.Parameters.AddWithValue("$id", id);

            using var reader = cmd.ExecuteReader();
            if (!reader.Read())
                return null;

            return new ClientObject
            {
                Id = reader.GetString(0),
                ClientId = reader.GetString(1),
                DisplayName = reader.GetString(2),
                IsActive = reader.GetBoolean(3),
                CreatedAt = reader.GetString(4)
            };
        });

        return client is not null
            ? ApiResult<ClientObject>.Ok(client)
            : ApiResult<ClientObject>.Fail("Updated client could not be retrieved.");
    }

    /// <summary>
    /// Retrieves a list of all active clients from the database.
    /// </summary>
    /// <remarks>This method queries the database for clients that are marked as active and returns them in
    /// ascending order of their client IDs. Each client is represented as a <see cref="ClientObject"/>
    /// object.</remarks>
    /// <returns>An <see cref="ApiResult{T}"/> containing a list of <see cref="ClientObject"/> objects representing the active
    /// clients. If no active clients are found, the list will be empty.</returns>
    public static ApiResult<List<ClientObject>> GetAllClients()
    {
        var clients = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
            SELECT id, client_identifier, display_name, created_at, is_active
            FROM clients
            WHERE is_active = 1
            ORDER BY client_identifier ASC;
        """;

            using var reader = cmd.ExecuteReader();
            var list = new List<ClientObject>();

            while (reader.Read())
            {
                list.Add(new ClientObject
                {
                    Id = reader.GetString(0),
                    ClientId = reader.GetString(1),
                    DisplayName = reader.IsDBNull(2) ? string.Empty : reader.GetString(2),
                    CreatedAt = reader.GetString(3),
                    IsActive = reader.GetInt64(4) == 1
                });
            }

            return list;
        });

        return ApiResult<List<ClientObject>>.Ok(clients);
    }

    /// <summary>
    /// Retrieves a client by its unique identifier.
    /// </summary>
    /// <remarks>This method queries the database for a client with the specified identifier. If a matching
    /// client is found, it is returned as part of a successful <see cref="ApiResult{T}"/>. If no client is found, a
    /// "Not Found" result is returned.</remarks>
    /// <param name="id">The unique identifier of the client to retrieve. Cannot be null or empty.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing the client object if found, or a "Not Found" result if no client exists
    /// with the specified identifier.</returns>
    public static ApiResult<ClientObject> GetClientById(string id)
    {
        var client = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
            SELECT id, client_identifier, display_name, created_at, is_active
            FROM clients
            WHERE id = $id
        """;
            cmd.Parameters.AddWithValue("$id", id);

            using var reader = cmd.ExecuteReader();
            if (!reader.Read())
                return null;

            return new ClientObject
            {
                Id = reader.GetString(0),
                ClientId = reader.GetString(1),
                DisplayName = reader.GetString(2),
                CreatedAt = reader.GetString(3),
                IsActive = reader.GetBoolean(4)
            };
        });

        return client is null
            ? ApiResult<ClientObject>.NotFound($"Client '{id}' not found.")
            : ApiResult<ClientObject>.Ok(client);
    }

    /// <summary>
    /// Deletes a client record from the database based on the specified client ID.
    /// </summary>
    /// <remarks>This method attempts to delete a client record from the database. If the deletion fails
    /// (e.g., due to a database error or if the client ID does not exist), the method returns a failure result.
    /// Additionally, an audit log entry is created for successful deletions, including optional metadata such as the
    /// actor's user ID, IP address, and user agent.</remarks>
    /// <param name="clientId">The unique identifier of the client to delete. Cannot be null or empty.</param>
    /// <param name="config">The application configuration used for logging and auditing. Cannot be null.</param>
    /// <param name="actorUserId">The ID of the user performing the operation, used for auditing. Optional.</param>
    /// <param name="ip">The IP address of the user performing the operation, used for auditing. Optional.</param>
    /// <param name="ua">The user agent string of the user performing the operation, used for auditing. Optional.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/> that indicates the result of the
    /// operation. Returns a success result if the client was deleted successfully; otherwise, returns a failure result
    /// with an error message.</returns>
    public static ApiResult<MessageResponse> DeleteClient(
        string clientId,
        AppConfig config,
        string? actorUserId = null,
        string? ip = null,
        string? ua = null)
    {
        // Revoke sessions
        Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "UPDATE sessions SET is_revoked = 1 WHERE client_identifier = $cid;";
            cmd.Parameters.AddWithValue("$cid", clientId);
            cmd.ExecuteNonQuery();
        });

        // Revoke refresh tokens
        Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "UPDATE refresh_tokens SET is_revoked = 1 WHERE client_identifier = $cid;";
            cmd.Parameters.AddWithValue("$cid", clientId);
            cmd.ExecuteNonQuery();
        });

        // Delete from client_scopes
        Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "DELETE FROM client_scopes WHERE client_id = $cid;";
            cmd.Parameters.AddWithValue("$cid", clientId);
            cmd.ExecuteNonQuery();
        });

        // Finally delete the client
        var deleted = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "DELETE FROM clients WHERE id = $id;";
            cmd.Parameters.AddWithValue("$id", clientId);

            try
            {
                return cmd.ExecuteNonQuery() > 0;
            }
            catch (SqliteException ex)
            {
                Log.Error(ex, "Failed to delete client {ClientId}", clientId);
                return false;
            }
        });

        if (!deleted)
            return ApiResult<MessageResponse>.Fail("Failed to delete client");

        AuditLogger.AuditLog(config, actorUserId, "delete_client", clientId, ip, ua);

        return ApiResult<MessageResponse>.Ok(new(true, $"Client '{clientId}' deleted"));
    }

    /// <summary>
    /// Retrieves the total number of clients currently stored in the system.
    /// </summary>
    /// <returns>The total count of clients as an integer. Returns 0 if no clients are stored.</returns>
    public static int GetClientCount() => ClientStore.GetClientCount();
}        
