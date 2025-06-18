using System.Text.Json.Serialization;
namespace madTypes.Api.Common;

public class PermissionObject
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = default!;
    [JsonPropertyName("name")]
    public string Name { get; set; } = default!;
}
