using System.Text.Json.Serialization;

namespace madTypes.Api.Responses;

public sealed class RevokeResponse
{
    [JsonPropertyName("jti")]
    public string Jti { get; init; } = string.Empty;
    [JsonPropertyName("status")]
    public string Status { get; init; } = "unknown"; // revoked, already_revoked, expired, not_found
    [JsonPropertyName("message")]
    public string Message { get; init; } = string.Empty;
}
