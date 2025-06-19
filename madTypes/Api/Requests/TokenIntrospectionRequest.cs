using System.Text.Json.Serialization;

namespace madTypes.Api.Requests;

public class TokenIntrospectionRequest
{
    [JsonPropertyName("token")]
    public string Token { get; set; } = string.Empty;
}
