using System.Text.Json.Serialization;

namespace madTypes.Api.Responses;

public sealed class SessionResponse
{
    [JsonPropertyName("id")]
    public string Id { get; init; } = string.Empty;
    [JsonPropertyName("user_id")]
    public string UserId { get; init; } = string.Empty;
    [JsonPropertyName("client_id")]
    public string ClientIdentifier { get; init; } = string.Empty;
    [JsonPropertyName("issued_at")]
    public DateTime IssuedAt { get; init; }
    [JsonPropertyName("expires_at")]
    public DateTime ExpiresAt { get; init; }
    [JsonPropertyName("is_revoked")]
    public bool IsRevoked { get; init; }
    [JsonPropertyName("token_use")]
    public string TokenUse { get; init; } = "auth";
}
