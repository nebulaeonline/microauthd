using System.Text.Json.Serialization;

namespace madTypes.Api.Common;

public class ClientRedirectUriObject
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;
    [JsonPropertyName("client_id")]
    public string ClientId { get; set; } = string.Empty;
    [JsonPropertyName("redirect_uri")]
    public string RedirectUri { get; set; } = string.Empty;
}
