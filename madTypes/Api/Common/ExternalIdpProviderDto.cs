using System.Text.Json.Serialization;

namespace madTypes.Api.Common;

public class ExternalIdpProviderDto
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;
    [JsonPropertyName("client_id")]
    public string ClientId { get; set; } = string.Empty;
    [JsonPropertyName("provider_key")]
    public string ProviderKey { get; set; } = string.Empty;
    [JsonPropertyName("display_name")]
    public string DisplayName { get; set; } = string.Empty;
    [JsonPropertyName("issuer")]
    public string Issuer { get; set; } = string.Empty;
    [JsonPropertyName("client_identifier")]
    public string ClientIdentifier { get; set; } = string.Empty;
    [JsonPropertyName("scopes")]
    public string Scopes { get; set; } = "openid email profile";
    [JsonPropertyName("created_at")]
    public DateTime CreatedAt { get; set; }
    [JsonPropertyName("modified_at")]
    public DateTime ModifiedAt { get; set; }
}
