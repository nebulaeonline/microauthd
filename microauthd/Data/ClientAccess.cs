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

public static class ClientAccess
{
    // returns a client by its ID, or null if not found
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
}
