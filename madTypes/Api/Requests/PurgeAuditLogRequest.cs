namespace madTypes.Api.Requests
{
    public record PurgeAuditLogRequest(int OlderThanDays);
}
