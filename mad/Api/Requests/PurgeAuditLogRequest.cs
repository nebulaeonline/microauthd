namespace mad.Api.Requests
{
    public record PurgeAuditLogRequest(int OlderThanDays);
}
