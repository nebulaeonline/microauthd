namespace madTypes.Api.Requests;

public sealed class AssignPermissionRequest
{
    public List<string> PermissionIds { get; init; } = new();
}
