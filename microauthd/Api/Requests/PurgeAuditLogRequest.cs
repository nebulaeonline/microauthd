namespace microauthd.Api.Requests
{
    public record PurgeAuditLogRequest(int OlderThanDays);
}
