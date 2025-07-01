using System.Text.Json.Serialization;

namespace madTypes.Api.Responses;

public class AuditLogResponse
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;
    [JsonPropertyName("actor_id")]
    public string? ActorId { get; set; }
    [JsonPropertyName("action")]
    public string Action { get; set; } = string.Empty;
    [JsonPropertyName("secondary")]
    public string? Secondary { get; set; }
    [JsonPropertyName("target")]
    public string? Target { get; set; }
    [JsonPropertyName("timestamp")]
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    [JsonPropertyName("ip_address")]
    public string? IpAddress { get; set; }
    [JsonPropertyName("user_agent")]
    public string? UserAgent { get; set; }
}
