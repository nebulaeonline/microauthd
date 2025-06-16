namespace mad.Api.Requests;

public sealed class CheckAccessRequest
{
    public string UserId { get; init; } = string.Empty;
    public string PermissionId { get; init; } = string.Empty;
}
