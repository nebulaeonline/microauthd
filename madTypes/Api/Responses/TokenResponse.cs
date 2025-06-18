using System.Text.Json.Serialization;

namespace madTypes.Api.Responses;

public sealed class TokenResponse
{
    [JsonPropertyName("access_token")]
    public string AccessToken { get; init; } = string.Empty;
    [JsonPropertyName("token_type")]
    public string TokenType { get; init; } = "bearer";
    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; init; }
    [JsonPropertyName("jti")]
    public string? Jti { get; init; }
    [JsonPropertyName("refresh_token")]
    public string? RefreshToken { get; init; }
    [JsonPropertyName("aud")]
    public string? Audience { get; init; } = "microauthd";
}
