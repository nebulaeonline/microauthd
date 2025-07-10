using System.Text.Json.Serialization;

namespace madTypes.Api.Responses;

public sealed class SessionResponse
{
    [JsonPropertyName("id")]
    public string Id { get; init; } = string.Empty;
    [JsonPropertyName("user_id")]
    public string UserId { get; init; } = string.Empty;
    [JsonPropertyName("username")]
    public string Username { get; init; } = string.Empty;
    [JsonPropertyName("client_id")]
    public string ClientIdentifier { get; init; } = string.Empty;
    [JsonPropertyName("issued_at")]
    public DateTime IssuedAt { get; init; }
    [JsonPropertyName("expires_at")]
    public DateTime ExpiresAt { get; init; }
    [JsonPropertyName("is_revoked")]
    public bool IsRevoked { get; init; }
    [JsonPropertyName("token_use")]
    public string TokenUse { get; init; } = string.Empty;
    [JsonPropertyName("mad_use")]
    public string MadUse { get; init; } = string.Empty;
    [JsonPropertyName("login_method")]
    public string LoginMethod { get; init; } = string.Empty;
    [JsonPropertyName("is_session_based")]
    public bool IsSessionBased { get; init; } = false;
    [JsonPropertyName("session_max_age")]
    public int SessionMaxAge { get; init; } = 0;
    [JsonPropertyName("session_expires_at")]
    public DateTime? SessionExpiresAt { get; init; } = null;
}
