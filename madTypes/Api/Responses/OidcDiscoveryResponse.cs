namespace madTypes.Api.Responses;

public sealed class OidcDiscoveryResponse
{
    public required string Issuer { get; init; }
    public required string TokenEndpoint { get; init; }
    public required string JwksUri { get; init; }

    public required string[] ResponseTypesSupported { get; init; }
    public required string[] SubjectTypesSupported { get; init; }
    public required string[] IdTokenSigningAlgValuesSupported { get; init; }
    public required string[] ScopesSupported { get; init; }
    public required string[] ClaimsSupported { get; init; }
}
