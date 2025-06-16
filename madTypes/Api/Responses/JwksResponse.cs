namespace madTypes.Api.Responses;

public sealed class JwksResponse
{
    public required List<JwkKey> Keys { get; init; }
}

public sealed class JwkKey
{
    public required string Kid { get; init; }
    public required string Kty { get; init; }
    public required string Alg { get; init; }
    public required string Use { get; init; }
    public required string N { get; init; }    // RSA only
    public required string E { get; init; }    // RSA only

    // Optional for EC keys
    public string? Crv { get; init; }
    public string? X { get; init; }
    public string? Y { get; init; }
}
