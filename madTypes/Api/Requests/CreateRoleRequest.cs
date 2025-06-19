using System.Text.Json.Serialization;

namespace madTypes.Api.Requests;

public sealed class CreateRoleRequest
{
    [JsonPropertyName("name")]
    public string Name { get; init; } = string.Empty;
    [JsonPropertyName("description")]
    public string? Description { get; init; }
}
