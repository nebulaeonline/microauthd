using System.Text.Json.Serialization;

namespace madTypes.Api.Common;

public class RoleObject
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = default!;
    [JsonPropertyName("name")]
    public string Name { get; set; } = default!;
    [JsonPropertyName("description")]
    public string? Description { get; set; }
    [JsonPropertyName("is_protected")]
    public bool IsProtected { get; set; }
    [JsonPropertyName("is_active")]
    public bool IsActive { get; set; } = true;
}
