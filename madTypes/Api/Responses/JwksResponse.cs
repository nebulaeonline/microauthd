using System.Text.Json.Serialization;

namespace madTypes.Api.Responses;

public sealed class JwksResponse
{
    [JsonPropertyName("keys")]
    public required List<JwkKey> Keys { get; init; }
}

public sealed class JwkKey
{
    [JsonPropertyName("kid")]
    public required string Kid { get; init; }
    [JsonPropertyName("kty")]
    public required string Kty { get; init; }
    [JsonPropertyName("alg")]
    public required string Alg { get; init; }
    [JsonPropertyName("use")]
    public required string Use { get; init; }
    [JsonPropertyName("n")]
    public required string N { get; init; }    // RSA only
    [JsonPropertyName("e")]
    public required string E { get; init; }    // RSA only

    // Optional for EC keys
    [JsonPropertyName("crv")]
    public string? Crv { get; init; }
    [JsonPropertyName("x")]
    public string? X { get; init; }
    [JsonPropertyName("y")]
    public string? Y { get; init; }
}
