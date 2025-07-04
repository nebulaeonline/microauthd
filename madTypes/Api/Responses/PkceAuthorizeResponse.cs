using System.Text.Json.Serialization;

namespace madTypes.Api.Responses;

public record PkceAuthorizeResponse(
    [property: JsonPropertyName("jti")]
    string Jti,
    [property: JsonPropertyName("client_id")]
    string ClientId,
    [property: JsonPropertyName("redirect_uri")]
    string RedirectUri,
    [property: JsonPropertyName("requires_totp")]
    bool RequiresTotp
);
