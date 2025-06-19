using System.Text.Json.Serialization;

namespace madTypes.Api.Requests;

public sealed class AssignRoleRequest
{
    [JsonPropertyName("user_id")]
    public string UserId { get; init; } = string.Empty;
    [JsonPropertyName("role_id")]
    public string RoleId { get; init; } = string.Empty;
}
