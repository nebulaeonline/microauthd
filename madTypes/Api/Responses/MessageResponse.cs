using System.Text.Json.Serialization;

namespace madTypes.Api.Responses;

public record MessageResponse(

    [property: JsonPropertyName("success")]
    bool Success,

    [property: JsonPropertyName("message")]
    string Message
);
