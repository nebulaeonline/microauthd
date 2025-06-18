using System.Text.Json.Serialization;

namespace madTypes.Api.Requests;

public sealed class TokenRequest
{
    [JsonPropertyName("username")]
    public string Username { get; init; } = string.Empty;
    [JsonPropertyName("password")]
    public string Password { get; init; } = string.Empty;
    [JsonPropertyName("client_id")]
    public string ClientIdentifier { get; init; } = string.Empty;
}
