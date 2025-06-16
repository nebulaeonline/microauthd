namespace madTypes.Api.Requests;

public sealed class AssignRoleRequest
{
    public string UserId { get; init; } = string.Empty;
    public string RoleId { get; init; } = string.Empty;
}
