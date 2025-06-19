using System.Text.Json.Serialization;

namespace madTypes.Api.Responses;

public record WhoamiResponse(
    [property: JsonPropertyName("message")]
    string Message
);
