using madTypes.Api.Common;
using madTypes.Api.Responses;
using Microsoft.Data.Sqlite;
using Microsoft.IdentityModel.Tokens;
using Serilog;

namespace microauthd.Data;

public class Client
{
    public string Id { get; init; } = string.Empty;
    public string ClientId { get; init; } = string.Empty;
    public string DisplayName { get; init; } = string.Empty;
    public string ClientSecretHash { get; init; } = string.Empty;
    public string Audience { get; init; } = string.Empty;
    public bool IsActive { get; init; }
}

/// <summary>
/// Provides methods for retrieving client information from the database.
/// </summary>
/// <remarks>The <see cref="ClientStore"/> class contains static methods for querying client-related data, such as
/// retrieving client details by ID or obtaining the audience associated with a client identifier. These methods
/// interact with the database and return the requested information.</remarks>
public static class ClientStore
{
    /// <summary>
    /// Creates a new client record in the database and returns the corresponding <see cref="ClientObject"/>.
    /// </summary>
    /// <remarks>This method inserts a new client record into the database and retrieves the created client
    /// details. If the insertion fails (e.g., due to a database constraint violation), the method returns <see
    /// langword="null"/>.</remarks>
    /// <param name="id">The unique identifier for the client. This value must be unique across all clients.</param>
    /// <param name="clientIdent">The client identifier used for authentication purposes.</param>
    /// <param name="secretHash">The hashed secret associated with the client for secure authentication.</param>
    /// <param name="displayName">The display name of the client. If null, an empty string will be used.</param>
    /// <param name="audience">The audience associated with the client. If null, the default value "microauthd" will be used.</param>
    /// <returns>A <see cref="ClientObject"/> representing the newly created client, or <see langword="null"/> if the client
    /// could not be created.</returns>
    public static ClientObject? CreateClient(string id, string clientIdent, string secretHash, string displayName, string audience)
    {
        var created = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                INSERT INTO clients (id, client_identifier, client_secret_hash, display_name, audience, created_at, modified_at, is_active)
                VALUES ($id, $cid, $hash, $name, $aud, datetime('now'), datetime('now'), 1);
            """;
            cmd.Parameters.AddWithValue("$id", id);
            cmd.Parameters.AddWithValue("$cid", clientIdent);
            cmd.Parameters.AddWithValue("$hash", secretHash);
            cmd.Parameters.AddWithValue("$name", displayName ?? "");
            cmd.Parameters.AddWithValue("$aud", audience);

            try
            {
                return cmd.ExecuteNonQuery() == 1;
            }
            catch (SqliteException)
            {
                return false;
            }
        });

        if (!created)
            return null;

        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
            SELECT id, client_identifier, display_name, audience, created_at, is_active
            FROM clients WHERE id = $id;
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
                Audience = reader.GetString(3),
                CreatedAt = reader.GetDateTime(4),
                IsActive = reader.GetBoolean(5)
            };
        });
    }

    /// <summary>
    /// Retrieves a client record from the database based on the specified client identifier.
    /// </summary>
    /// <remarks>This method queries the database for a client with the specified identifier. If no matching
    /// client is found, the method returns <see langword="null"/>. The returned <see cref="Client"/> object includes
    /// details such as the client's ID, display name, secret hash, and active status.</remarks>
    /// <param name="clientIdentifier">The unique identifier of the client to retrieve. This value must not be null or empty.</param>
    /// <returns>A <see cref="Client"/> object representing the client if found; otherwise, <see langword="null"/>.</returns>
    public static Client? GetClientByClientIdentifier(string clientIdentifier)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT id, client_identifier, display_name, audience, client_secret_hash, is_active
                FROM clients
                WHERE client_identifier = $cid
                LIMIT 1;
            """;
            cmd.Parameters.AddWithValue("$cid", clientIdentifier);

            using var reader = cmd.ExecuteReader();
            if (!reader.Read())
                return null;

            return new Client
            {
                Id = reader.GetString(0),
                ClientId = reader.GetString(1),
                DisplayName = reader.IsDBNull(2) ? "" : reader.GetString(2),
                Audience = reader.GetString(3),
                ClientSecretHash = reader.GetString(4),
                IsActive = reader.GetBoolean(5)
            };
        });
    }

    /// <summary>
    /// Updates the client record in the database with the specified values.
    /// </summary>
    /// <remarks>This method performs an update operation on the database. If the specified <paramref
    /// name="id"/> does not  match any existing client record, the method will return <see langword="false"/> without
    /// making any changes. The <paramref name="updated"/> object must contain valid data for the update operation to
    /// succeed.</remarks>
    /// <param name="id">The unique identifier of the client to update. This value must match an existing client record.</param>
    /// <param name="updated">An object containing the updated client information. The <see cref="ClientObject.ClientId"/>,  <see
    /// cref="ClientObject.Audience"/>, and optionally <see cref="ClientObject.DisplayName"/> properties  are used to
    /// update the corresponding fields in the database.</param>
    /// <returns><see langword="true"/> if the client record was successfully updated; otherwise, <see langword="false"/>.</returns>
    public static bool UpdateClient(string id, ClientObject updated)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                UPDATE clients
                SET client_identifier = $cid,
                    audience = $aud,
                    display_name = $name,
                    modified_at = datetime('now')
                WHERE id = $id;
            """;
            cmd.Parameters.AddWithValue("$cid", updated.ClientId);
            cmd.Parameters.AddWithValue("$name", updated.DisplayName ?? "");
            cmd.Parameters.AddWithValue("$aud", updated.Audience);
            cmd.Parameters.AddWithValue("$id", id);
            return cmd.ExecuteNonQuery() == 1;
        });
    }

    /// <summary>
    /// Determines whether a client identifier exists in the database.
    /// </summary>
    /// <remarks>This method queries the database to check for the presence of the specified client
    /// identifier. It performs a case-sensitive comparison and returns <see langword="false"/> if the identifier is not
    /// found.</remarks>
    /// <param name="clientId">The client identifier to check for existence. Cannot be null or empty.</param>
    /// <returns><see langword="true"/> if the specified client identifier exists in the database;  otherwise, <see
    /// langword="false"/>. </returns>
    public static bool DoesClientIdExist(string id, string clientId)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT COUNT(*) FROM clients WHERE id != $id AND client_identifier = $cid;";
            cmd.Parameters.AddWithValue("$id", id);
            cmd.Parameters.AddWithValue("$cid", clientId);
            var result = cmd.ExecuteScalar();
            return result != null && Convert.ToInt32(result) > 0;
        });
    }

    /// <summary>
    /// Retrieves a <see cref="ClientObject"/> instance by its unique identifier.
    /// </summary>
    /// <remarks>This method queries the database to retrieve client information based on the provided
    /// identifier. Ensure that the <paramref name="id"/> parameter corresponds to a valid client record in the
    /// database.</remarks>
    /// <param name="id">The unique identifier of the client object to retrieve. Cannot be null or empty.</param>
    /// <returns>A <see cref="ClientObject"/> representing the client with the specified identifier,  or <see langword="null"/>
    /// if no matching client is found.</returns>
    public static ClientObject? GetClientObjById(string id)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT id, client_identifier, display_name, audience, is_active, created_at
                FROM clients
                WHERE id = $id
                LIMIT 1;
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
                Audience = reader.GetString(3),
                IsActive = reader.GetBoolean(4),
                CreatedAt = reader.GetDateTime(5)
            };
        });
    }

    /// <summary>
    /// Retrieves a client record from the database by its unique identifier.
    /// </summary>
    /// <remarks>This method queries the database for a client record with the specified identifier.  If a
    /// matching record is found, it is mapped to a <see cref="Client"/> object.  If no record is found, the method
    /// returns <see langword="null"/>.</remarks>
    /// <param name="id">The unique identifier of the client to retrieve. This value must not be null or empty.</param>
    /// <returns>A <see cref="Client"/> object representing the client with the specified identifier,  or <see langword="null"/>
    /// if no matching client is found.</returns>
    public static Client? GetClientById(string id)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT id, client_identifier, display_name, audience, client_secret_hash, is_active
                FROM clients
                WHERE id = $id
                LIMIT 1;
            """;
            cmd.Parameters.AddWithValue("$id", id);

            using var reader = cmd.ExecuteReader();
            if (!reader.Read())
                return null;

            return new Client
            {
                Id = reader.GetString(0),
                ClientId = reader.GetString(1),
                DisplayName = reader.IsDBNull(2) ? "" : reader.GetString(2),
                Audience = reader.GetString(3),
                ClientSecretHash = reader.GetString(4),
                IsActive = reader.GetBoolean(5)
            };
        });
    }

    /// <summary>
    /// Retrieves the client ID associated with the specified client identifier.
    /// </summary>
    /// <remarks>This method queries the database to find the client ID associated with the given client
    /// identifier. If no matching record exists, the method returns <see langword="null"/>.</remarks>
    /// <param name="clientIdentifier">The unique identifier of the client. This value is used to query the database for the corresponding client ID.</param>
    /// <returns>The client ID as a string if a matching record is found; otherwise, <see langword="null"/>.</returns>
    public static string? GetClientIdByIdentifier(string clientIdentifier)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT id FROM clients WHERE client_id = $client_id LIMIT 1;";
            cmd.Parameters.AddWithValue("$client_id", clientIdentifier);

            var result = cmd.ExecuteScalar();
            return result == null ? null : Convert.ToString(result);
        });
    }

    /// <summary>
    /// Retrieves the audience associated with the specified client identifier.
    /// </summary>
    /// <remarks>This method queries the database to retrieve the audience for the given client identifier. If
    /// the client identifier does not exist in the database, the method returns the default audience value.</remarks>
    /// <param name="clientIdentifier">The unique identifier of the client whose audience is to be retrieved. Must not be <see langword="null"/> or
    /// empty.</param>
    /// <returns>A string representing the audience associated with the specified client identifier. If no audience is found,
    /// returns the default value "microauthd".</returns>
    public static string? GetClientAudienceByIdentifier(string clientIdentifier)
    {
        var audience = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT audience FROM clients
                WHERE client_identifier = $cid LIMIT 1;
            """;
            cmd.Parameters.AddWithValue("$cid", clientIdentifier);
            using var reader = cmd.ExecuteReader();
            return reader.Read() ? reader.GetString(0) : null;

        });

        return audience;
    }

    /// <summary>
    /// Retrieves the hashed client secret associated with the specified client identifier.
    /// </summary>
    /// <remarks>This method queries the database to retrieve the client secret hash for the given identifier.
    /// If no matching client is found, an empty string is returned.</remarks>
    /// <param name="clientIdentifier">The unique identifier of the client whose secret hash is to be retrieved. Must not be <see langword="null"/> or
    /// empty.</param>
    /// <returns>The hashed client secret as a <see cref="string"/> if the client identifier exists;  otherwise, an empty string.</returns>
    public static string GetClientSecretHashByIdentifier(string clientIdentifier)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT client_secret_hash FROM clients
                WHERE client_identifier = $cid LIMIT 1;
            """;
            cmd.Parameters.AddWithValue("$cid", clientIdentifier);
            using var reader = cmd.ExecuteReader();
            return reader.Read() ? reader.GetString(0) : string.Empty;
        });
    }

    /// <summary>
    /// Updates the client secret hash for an active client identified by the specified client ID.
    /// </summary>
    /// <remarks>This method updates the client secret hash and the modification timestamp for the specified
    /// client. The operation will only succeed if the client is active.</remarks>
    /// <param name="clientId">The unique identifier of the client whose secret hash is to be updated.  Must correspond to an active client in
    /// the database.</param>
    /// <param name="newHash">The new hashed value of the client secret to be stored in the database.</param>
    /// <returns><see langword="true"/> if the client secret was successfully updated; otherwise, <see langword="false"/>.</returns>
    public static bool UpdateClientSecret(string clientId, string newHash)
    {
        const string sql = """
            UPDATE clients
            SET client_secret_hash = $hash,
                modified_at = datetime('now')
            WHERE id = $id AND is_active = 1;
        """;

        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = sql;
            cmd.Parameters.AddWithValue("$hash", newHash);
            cmd.Parameters.AddWithValue("$id", clientId);
            return cmd.ExecuteNonQuery() == 1;
        });
    }

    /// <summary>
    /// Retrieves a list of active scopes associated with the specified client identifier.
    /// </summary>
    /// <remarks>This method queries the database to retrieve scopes that are active and associated with the
    /// specified client. The client, scopes, and their associations must all be marked as active for a scope to be
    /// included in the result.</remarks>
    /// <param name="clientIdentifier">The unique identifier of the client whose scopes are to be retrieved. This value must not be null or empty.</param>
    /// <returns>A list of strings representing the names of active scopes associated with the client. If no active scopes are
    /// found, an empty list is returned.</returns>
    public static List<string> GetClientScopes(string clientIdentifier)
    {
        var scopes = Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT s.name
                FROM client_scopes cs
                JOIN scopes s ON cs.scope_id = s.id
                JOIN clients c ON cs.client_id = c.id
                WHERE c.client_identifier = $cid AND cs.is_active = 1 AND s.is_active = 1 AND c.is_active = 1;
            """;
            cmd.Parameters.AddWithValue("$cid", clientIdentifier);

            using var reader = cmd.ExecuteReader();
            var list = new List<string>();
            while (reader.Read())
                list.Add(reader.GetString(0));
            return list;
        });

        return scopes;
    }

    /// <summary>
    /// Retrieves a list of all clients from the database.
    /// </summary>
    /// <remarks>This method queries the database to fetch all client records, including their identifiers,
    /// display names,  audience information, active status, and creation timestamps. The results are ordered by the
    /// display name.</remarks>
    /// <returns>A list of <see cref="ClientObject"/> instances representing all clients in the database.  The list will be empty
    /// if no clients are found.</returns>
    public static List<ClientObject> ListAllClients()
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT id, client_identifier, display_name, audience, is_active, created_at
                FROM clients
                ORDER BY display_name;
            """;
            using var reader = cmd.ExecuteReader();
            var results = new List<ClientObject>();
            
            while (reader.Read())
            {
                results.Add(new ClientObject
                {
                    Id = reader.GetString(0),
                    ClientId = reader.GetString(1),
                    DisplayName = reader.GetString(2),
                    Audience = reader.GetString(3),
                    IsActive = reader.GetBoolean(4),
                    CreatedAt = reader.GetDateTime(5)
                });
            }
            return results;
        });
    }

    /// <summary>
    /// Retrieves a paginated list of active clients from the database.
    /// </summary>
    /// <remarks>This method queries the database for clients that are marked as active and returns them in
    /// ascending order by name. Use the <paramref name="offset"/> and <paramref name="limit"/> parameters to control
    /// pagination.</remarks>
    /// <param name="offset">The zero-based index of the first client to retrieve. Must be non-negative.</param>
    /// <param name="limit">The maximum number of clients to retrieve. Must be greater than zero.</param>
    /// <returns>A list of <see cref="ClientObject"/> instances representing active clients. The list will be empty if no active
    /// clients are found within the specified range.</returns>
    public static List<ClientObject> ListClients(int offset = 0, int limit = 50)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                SELECT id, client_identifier, display_name, audience, is_active, created_at
                FROM clients
                WHERE is_active = 1
                ORDER BY display_name
                LIMIT $limit OFFSET $offset
            """;
            cmd.Parameters.AddWithValue("$limit", limit);
            cmd.Parameters.AddWithValue("$offset", offset);

            using var reader = cmd.ExecuteReader();
            var results = new List<ClientObject>();
            
            while (reader.Read())
            {
                results.Add(new ClientObject
                {
                    Id = reader.GetString(0),
                    ClientId = reader.GetString(1),
                    DisplayName = reader.GetString(2),
                    Audience = reader.GetString(3),
                    IsActive = reader.GetBoolean(4),
                    CreatedAt = reader.GetDateTime(5)

                });
            }
            return results;
        });
    }

    /// <summary>
    /// Revokes all active sessions associated with the specified client identifier.
    /// </summary>
    /// <remarks>This method marks all sessions for the specified client as inactive by updating the database.
    /// The <c>modified_at</c> field is also updated to the current timestamp.</remarks>
    /// <param name="clientIdent">The unique identifier of the client whose sessions should be revoked.  This value must match the
    /// <c>client_identifier</c> field in the database.</param>
    public static void RevokeClientSessions(string clientIdent)
    {
        Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                UPDATE sessions
                SET is_revoked = 1
                WHERE client_identifier = $cid;
            """;
            cmd.Parameters.AddWithValue("$cid", clientIdent);
            cmd.ExecuteNonQuery();
        });
    }

    /// <summary>
    /// Revokes all active refresh tokens associated with the specified client identifier.
    /// </summary>
    /// <remarks>This method updates the database to mark all refresh tokens for the specified client as
    /// inactive. It is typically used to invalidate tokens when a client is deauthorized or compromised.</remarks>
    /// <param name="clientIdent">The unique identifier of the client whose refresh tokens should be revoked. This value must not be null or
    /// empty.</param>
    public static void RevokeClientRefreshTokens(string clientIdent)
    {
        Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                UPDATE refresh_tokens
                SET is_revoked = 1
                WHERE client_identifier = $cid;
            """;
            cmd.Parameters.AddWithValue("$cid", clientIdent);
            cmd.ExecuteNonQuery();
        });
    }

    /// <summary>
    /// Deletes all client scopes associated with the specified client identifier.
    /// </summary>
    /// <remarks>This method removes all entries in the <c>client_scopes</c> table that are linked to the 
    /// client specified by <paramref name="clientIdent"/>. The client is identified by its  <c>client_identifier</c> in
    /// the <c>clients</c> table.</remarks>
    /// <param name="clientIdent">The unique identifier of the client whose scopes are to be deleted.  This value must not be null or empty.</param>
    public static void DeleteClientScopes(string clientIdent)
    {
        Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                DELETE FROM client_scopes
                WHERE client_id = (SELECT id FROM clients WHERE client_identifier = $cid);
            """;
            cmd.Parameters.AddWithValue("$cid", clientIdent);
            cmd.ExecuteNonQuery();
        });
    }

    /// <summary>
    /// Deletes a client record from the database based on the specified client ID.
    /// </summary>
    /// <remarks>This method attempts to delete a client record from the database using the provided client
    /// ID. If the operation fails due to a database error, the method logs the error and returns <see
    /// langword="false"/>.</remarks>
    /// <param name="id">The unique identifier of the client to delete. Cannot be null or empty.</param>
    /// <returns><see langword="true"/> if the client record was successfully deleted; otherwise, <see langword="false"/>. </returns>
    public static bool DeleteClient(string id)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "DELETE FROM clients WHERE id = $id;";
            cmd.Parameters.AddWithValue("$id", id);

            return cmd.ExecuteNonQuery() > 0;            
        });
    }

    /// <summary>
    /// Deletes a client record from the database based on the specified client identifier.
    /// </summary>
    /// <remarks>This method executes a SQL DELETE operation to remove the client record associated with the
    /// given identifier. Ensure that the database connection is properly configured and accessible.</remarks>
    /// <param name="clientId">The unique identifier of the client to be deleted. This value must not be <see langword="null"/> or empty.</param>
    /// <returns><see langword="true"/> if the client record was successfully deleted; otherwise, <see langword="false"/>.</returns>
    public static bool DeleteClientByClientId(string clientId)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "DELETE FROM clients WHERE client_identifier = $cid;";
            cmd.Parameters.AddWithValue("$cid", clientId);
            return cmd.ExecuteNonQuery() > 0;
        });
    }

    /// <summary>
    /// Inserts a new redirect URI for the specified client into the database.
    /// </summary>
    /// <remarks>This method generates a new unique identifier for the redirect URI and attempts to insert  it
    /// into the database. If the operation is successful, a <see cref="ClientRedirectUriObject"/>  containing the
    /// details of the inserted redirect URI is returned. If an error occurs during  the database operation, the method
    /// logs the error and returns <see langword="null"/>.</remarks>
    /// <param name="clientId">The unique identifier of the client for which the redirect URI is being added. Must not be null, empty, or
    /// consist solely of whitespace.</param>
    /// <param name="uri">The redirect URI to associate with the client.  Must not be null, empty, or consist solely of whitespace.</param>
    /// <returns>A <see cref="ClientRedirectUriObject"/> representing the newly inserted redirect URI,  or <see langword="null"/>
    /// if the operation fails or if either <paramref name="clientId"/>  or <paramref name="uri"/> is invalid.</returns>
    public static ClientRedirectUriObject? InsertRedirectUri(string clientId, string uri)
    {
        if (string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(uri))
            return null;

        var id = Guid.NewGuid().ToString();

        try
        {
            Db.WithConnection(conn =>
            {
                using var cmd = conn.CreateCommand();
                cmd.CommandText = """
                    INSERT INTO redirect_uris (id, client_id, uri)
                    VALUES ($id, $client_id, $uri);
                """;
                cmd.Parameters.AddWithValue("$id", id);
                cmd.Parameters.AddWithValue("$client_id", clientId);
                cmd.Parameters.AddWithValue("$uri", uri);
                cmd.ExecuteNonQuery();
            });

            return new ClientRedirectUriObject
            {
                Id = id,
                ClientId = clientId,
                RedirectUri = uri
            };
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to insert redirect URI for client {ClientId}", clientId);
            return null;
        }
    }

    /// <summary>
    /// Retrieves a list of redirect URIs associated with the specified client ID.
    /// </summary>
    /// <remarks>This method queries the database to retrieve redirect URIs for the given client ID. The
    /// results are ordered by the URI value.</remarks>
    /// <param name="clientId">The unique identifier of the client for which redirect URIs are to be retrieved. Must not be <see
    /// langword="null"/> or empty.</param>
    /// <returns>A list of <see cref="ClientRedirectUriObject"/> instances representing the redirect URIs associated with the
    /// specified client ID. Returns an empty list if no redirect URIs are found.</returns>
    public static List<ClientRedirectUriObject> GetRedirectUrisByClientId(string clientId)
    {
        var list = new List<ClientRedirectUriObject>();

        Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
            SELECT id, client_id, uri
            FROM redirect_uris
            WHERE client_id = $cid
            ORDER BY uri;
        """;
            cmd.Parameters.AddWithValue("$cid", clientId);

            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                list.Add(new ClientRedirectUriObject
                {
                    Id = reader.GetString(0),
                    ClientId = reader.GetString(1),
                    RedirectUri = reader.GetString(2)
                });
            }
        });

        return list;
    }

    /// <summary>
    /// Deletes a redirect URI from the database based on its unique identifier.
    /// </summary>
    /// <remarks>This method executes a database operation to remove the specified redirect URI.  Ensure that
    /// the provided <paramref name="id"/> corresponds to an existing record.</remarks>
    /// <param name="id">The unique identifier of the redirect URI to delete. This value cannot be null or empty.</param>
    /// <returns><see langword="true"/> if the redirect URI was successfully deleted; otherwise, <see langword="false"/>.</returns>
    public static bool DeleteRedirectUriById(string id)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "DELETE FROM redirect_uris WHERE id = $id;";
            cmd.Parameters.AddWithValue("$id", id);
            var rowsAffected = cmd.ExecuteNonQuery();
            return rowsAffected > 0;
        });
    }

    /// <summary>
    /// Retrieves the count of active clients from the database.
    /// </summary>
    /// <remarks>This method queries the database to count the number of clients marked as active.  It assumes
    /// that the database connection is properly configured and accessible.</remarks>
    /// <returns>The total number of active clients as an integer. Returns 0 if no active clients are found.</returns>
    public static int GetClientCount()
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT COUNT(*) FROM clients WHERE is_active = 1;";
            return Convert.ToInt32(cmd.ExecuteScalar());
        });
    }
}
