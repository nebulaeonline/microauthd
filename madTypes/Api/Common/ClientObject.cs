using System.Text.Json.Serialization;

namespace madTypes.Api.Common;

public sealed class ClientObject
{
    [JsonPropertyName("id")]
    public string Id { get; init; } = string.Empty;
    [JsonPropertyName("client_id")]
    public string ClientId { get; init; } = string.Empty;
    [JsonPropertyName("display_name")]
    public string DisplayName { get; init; } = string.Empty;
    [JsonPropertyName("is_active")]
    public bool IsActive { get; init; }
    [JsonPropertyName("created_at")]
    public string CreatedAt { get; init; } = string.Empty;
}
