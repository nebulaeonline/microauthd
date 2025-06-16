namespace mad.Api.Responses;

public record AccessCheckResponse(string UserId, string PermissionId, bool Allowed);
