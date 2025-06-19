using System.Text.Json.Serialization;

namespace madTypes.Api.Requests;

public sealed class CheckAccessRequest
{
    [JsonPropertyName("user_id")]
    public string UserId { get; init; } = string.Empty;
    [JsonPropertyName("permission_id")]
    public string PermissionId { get; init; } = string.Empty;
}
