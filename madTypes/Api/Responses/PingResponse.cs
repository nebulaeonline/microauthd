using System.Text.Json.Serialization;

namespace madTypes.Api.Responses;

public record PingResponse(
    [property: JsonPropertyName("message")]
    string Message
);
