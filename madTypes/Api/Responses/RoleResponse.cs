using System.Text.Json.Serialization;

namespace madTypes.Api.Responses;

public class RoleResponse
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = default!;
    [JsonPropertyName("name")]
    public string Name { get; set; } = default!;
    [JsonPropertyName("description")]
    public string? Description { get; set; }
    [JsonPropertyName("is_protected")]
    public bool IsProtected { get; set; }
}
