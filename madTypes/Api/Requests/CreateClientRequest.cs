using System.Text.Json.Serialization;

namespace madTypes.Api.Requests;

public sealed class CreateClientRequest
{
    [JsonPropertyName("client_id")]
    public string ClientId { get; init; } = string.Empty;
    [JsonPropertyName("client_secret")]
    public string ClientSecret { get; init; } = string.Empty;
    [JsonPropertyName("display_name")]
    public string? DisplayName { get; init; }
    [JsonPropertyName("audience")]
    public string? Audience { get; init; }
}
