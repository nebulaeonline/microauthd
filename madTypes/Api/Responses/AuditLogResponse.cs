using System.Text.Json.Serialization;

namespace madTypes.Api.Responses;

public class AuditLogResponse
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = "";
    [JsonPropertyName("user_id")]
    public string? UserId { get; set; }
    [JsonPropertyName("action")]
    public string Action { get; set; } = "";
    [JsonPropertyName("target")]
    public string? Target { get; set; }
    [JsonPropertyName("timestamp")]
    public string Timestamp { get; set; } = "";
    [JsonPropertyName("ip_address")]
    public string? IpAddress { get; set; }
    [JsonPropertyName("user_agent")]
    public string? UserAgent { get; set; }
}
