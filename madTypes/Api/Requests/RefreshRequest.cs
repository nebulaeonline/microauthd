using System.Text.Json.Serialization;

namespace madTypes.Api.Requests;

public sealed class RefreshRequest
{
    [JsonPropertyName("refresh_token")]
    public string RefreshToken { get; init; } = string.Empty;
}
