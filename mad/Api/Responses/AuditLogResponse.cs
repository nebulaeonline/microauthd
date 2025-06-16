namespace mad.Api.Responses;

public class AuditLogResponse
{
    public string Id { get; set; } = "";
    public string? UserId { get; set; }
    public string Action { get; set; } = "";
    public string? Target { get; set; }
    public string Timestamp { get; set; } = "";
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
}
