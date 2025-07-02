using System.Text.Json.Serialization;

namespace madTypes.Api.Responses;

public sealed class OidcDiscoveryResponse
{
    [JsonPropertyName("issuer")]
    public required string Issuer { get; init; }
    [JsonPropertyName("token_endpoint")]
    public required string TokenEndpoint { get; init; }
    [JsonPropertyName("jwks_uri")]
    public required string JwksUri { get; init; }
    [JsonPropertyName("response_types_supported")]
    public required string[] ResponseTypesSupported { get; init; }
    [JsonPropertyName("subject_types_supported")]
    public required string[] SubjectTypesSupported { get; init; }
    [JsonPropertyName("id_token_signing_alg_values_supported")]
    public required string[] IdTokenSigningAlgValuesSupported { get; init; }
    [JsonPropertyName("scopes_supported")]
    public required string[] ScopesSupported { get; init; }
    [JsonPropertyName("claims_supported")]
    public required string[] ClaimsSupported { get; init; }
    [JsonPropertyName("userinfo_endpoint")]
    public required string UserInfoEndpoint { get; init; }
    [JsonPropertyName("authorization_ui_endpoint")]
    public required string AuthorizationUIEndpoint { get; init; }
}
