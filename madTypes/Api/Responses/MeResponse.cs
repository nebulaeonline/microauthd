using System.Text.Json.Serialization;

namespace madTypes.Api.Responses;

public record MeResponse(
    [property: JsonPropertyName("sub")]
    string Subject,
    [property: JsonPropertyName("email")]
    string? Email,
    [property: JsonPropertyName("roles")]
    List<string> Roles,
    [property: JsonPropertyName("scopes")]
    List<string> Scopes
);
