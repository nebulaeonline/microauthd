using System.Text.Json.Serialization;

namespace madTypes.Api.Responses;

public sealed class SessionStatusResponse
{
    [JsonPropertyName("success")]
    public bool Success { get; init; } = true;

    [JsonPropertyName("sub")]
    public string Subject { get; init; } = string.Empty;

    [JsonPropertyName("role")]
    public string Role { get; init; } = string.Empty;

    [JsonPropertyName("expires_at")]
    public string ExpiresAt { get; init; } = string.Empty;

    [JsonPropertyName("token_use")]
    public string TokenUse { get; init; } = string.Empty;
}
