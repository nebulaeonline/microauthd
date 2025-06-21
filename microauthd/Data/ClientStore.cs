using madTypes.Api.Responses;

namespace microauthd.Data;

public class Client
{
    public string Id { get; init; } = string.Empty;
    public string ClientId { get; init; } = string.Empty;
    public string DisplayName { get; init; } = string.Empty;
    public string ClientSecretHash { get; init; } = string.Empty;
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
    /// Retrieves a client record from the database based on the specified client identifier.
    /// </summary>
    /// <remarks>This method queries the database for a client with the specified identifier. If no matching
    /// client is found, the method returns <see langword="null"/>. The returned <see cref="Client"/> object includes
    /// details such as the client's ID, display name, secret hash, and active status.</remarks>
    /// <param name="clientId">The unique identifier of the client to retrieve. This value must not be null or empty.</param>
    /// <returns>A <see cref="Client"/> object representing the client if found; otherwise, <see langword="null"/>.</returns>
    public static Client? GetClientById(string clientId)
    {
        return Db.WithConnection(conn =>
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
            SELECT id, client_identifier, display_name, client_secret_hash, is_active
            FROM clients
            WHERE client_identifier = $id
            LIMIT 1;
        """;
            cmd.Parameters.AddWithValue("$id", clientId);

            using var reader = cmd.ExecuteReader();
            if (!reader.Read())
                return null;

            return new Client
            {
                Id = reader.GetString(0),
                ClientId = reader.GetString(1),
                DisplayName = reader.IsDBNull(2) ? "" : reader.GetString(2),
                ClientSecretHash = reader.GetString(3),
                IsActive = reader.GetBoolean(4)
            };
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
    public static string GetClientAudienceByIdentifier(string clientIdentifier)
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

        }) ?? "microauthd";

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
