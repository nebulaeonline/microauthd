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
    [JsonPropertyName("grant_types_supported")]
    public required string[] GrantTypesSupported { get; init; }
    [JsonPropertyName("response_types_supported")]
    public required string[] ResponseTypesSupported { get; init; }
    [JsonPropertyName("token_endpoint_auth_methods_supported")]
    public required string[] TokenEndpointAuthMethodsSupported { get; init; }
    [JsonPropertyName("response_modes_supported")]
    public required string[] ResponseModesSupported { get; init; }
    [JsonPropertyName("code_challenge_methods_supported")]
    public required string[] CodeChallengeMethodsSupported { get; init; }
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
}
