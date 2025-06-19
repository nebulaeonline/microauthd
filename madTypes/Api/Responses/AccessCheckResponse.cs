using System.Text.Json.Serialization;

namespace madTypes.Api.Responses;

public record AccessCheckResponse(
    [property: JsonPropertyName("user_id")]
    string UserId,
    [property: JsonPropertyName("permission_id")]
    string PermissionId,
    [property: JsonPropertyName("allowed")]
    bool Allowed
);
