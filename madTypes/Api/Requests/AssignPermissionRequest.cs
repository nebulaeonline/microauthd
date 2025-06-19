using System.Text.Json.Serialization;
namespace madTypes.Api.Requests;

public sealed class AssignPermissionRequest
{
    [JsonPropertyName("permission_id")]
    public string PermissionId { get; set; } = string.Empty;
}
