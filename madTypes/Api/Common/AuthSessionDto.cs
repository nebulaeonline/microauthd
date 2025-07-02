using System.Text.Json.Serialization;

namespace madTypes.Api.Common;

public class AuthSessionDto
{
    [JsonPropertyName("jti")]
    public string Jti { get; set; } = default!;
    [JsonPropertyName("query_string")]
    public string QueryString { get; set; } = default!;
    [JsonPropertyName("created_at_utc")]
    public DateTime CreatedAtUtc { get; set; }
    [JsonPropertyName("expires_at_utc")]
    public DateTime ExpiresAtUtc { get; set; }
}
