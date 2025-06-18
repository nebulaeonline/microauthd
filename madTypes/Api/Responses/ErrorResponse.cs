using System.Text.Json.Serialization;

namespace madTypes.Api.Responses;

public record ErrorResponse(

    [property: JsonPropertyName("success")]
    bool Success,

    [property: JsonPropertyName("message")]
    string Message
);
