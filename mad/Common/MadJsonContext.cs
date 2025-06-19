using System.Text.Json.Serialization;

using madTypes.Api.Responses;
using madTypes.Api.Requests;
using madTypes.Api.Common;

namespace mad.Common;

[JsonSourceGenerationOptions(
    WriteIndented = false)]
[JsonSerializable(typeof(object))] // fallback
[JsonSerializable(typeof(List<string>))]
[JsonSerializable(typeof(ErrorResponse))]
[JsonSerializable(typeof(TokenResponse))]
[JsonSerializable(typeof(TokenRequest))]
[JsonSerializable(typeof(CreateUserRequest))]
[JsonSerializable(typeof(UserObject))]
[JsonSerializable(typeof(List<UserObject>))]
[JsonSerializable(typeof(CreateRoleRequest))]
[JsonSerializable(typeof(AssignRoleRequest))]
[JsonSerializable(typeof(ScopeObject))]
[JsonSerializable(typeof(List<ScopeObject>))]
[JsonSerializable(typeof(AssignScopesRequest))]
[JsonSerializable(typeof(CreatePermissionRequest))]
[JsonSerializable(typeof(AssignPermissionRequest))]
[JsonSerializable(typeof(CheckAccessRequest))]
[JsonSerializable(typeof(AccessCheckResponse))]
[JsonSerializable(typeof(CreateClientRequest))]
[JsonSerializable(typeof(ClientObject))]
[JsonSerializable(typeof(List<ClientObject>))]
[JsonSerializable(typeof(RoleObject))]
[JsonSerializable(typeof(List<RoleObject>))]
[JsonSerializable(typeof(PermissionObject))]
[JsonSerializable(typeof(List<PermissionObject>))]
[JsonSerializable(typeof(SessionResponse))]
[JsonSerializable(typeof(List<SessionResponse>))]
[JsonSerializable(typeof(CreatedResponse))]
[JsonSerializable(typeof(List<CreatedResponse>))]
[JsonSerializable(typeof(AuditLogResponse))]
[JsonSerializable(typeof(List<AuditLogResponse>))]
[JsonSerializable(typeof(PurgeAuditLogRequest))]
[JsonSerializable(typeof(PurgeTokensRequest))]
[JsonSerializable(typeof(RefreshTokenResponse))]
[JsonSerializable(typeof(List<RefreshTokenResponse>))]
[JsonSerializable(typeof(MessageResponse))]
[JsonSerializable(typeof(SessionStatusResponse))]
[JsonSerializable(typeof(LoginResponse))]
[JsonSerializable(typeof(Dictionary<string, object>))]
[JsonSerializable(typeof(bool))]
[JsonSerializable(typeof(int))]
[JsonSerializable(typeof(long))]
[JsonSerializable(typeof(double))]
[JsonSerializable(typeof(DateTime))]
public partial class MadJsonContext : JsonSerializerContext { }
