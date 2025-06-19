using System.Text.Json.Serialization;

namespace madTypes.Api.Requests;

public sealed class CreatePermissionRequest
{
    [JsonPropertyName("name")]
    public string Name { get; init; } = string.Empty;
}
