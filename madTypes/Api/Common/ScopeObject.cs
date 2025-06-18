using System.Text.Json.Serialization;
namespace madTypes.Api.Common;

public sealed class ScopeObject
{
    [JsonPropertyName("id")]
    public string Id { get; init; } = string.Empty;
    [JsonPropertyName("name")]
    public string Name { get; init; } = string.Empty;
    [JsonPropertyName("desc")]
    public string? Description { get; init; }
    [JsonPropertyName("is_active")]
    public bool IsActive { get; init; }
    [JsonPropertyName("created_at")]
    public string CreatedAt { get; init; } = string.Empty;
}
