using System.Text.Json.Serialization;

using microauthd.Config;
using madTypes.Api.Requests;
using madTypes.Api.Responses;
using madTypes.Api.Common;

namespace microauthd.Common;

// Our JsonSerializerContext must be annotated
// with all the types we intend to serialize &
// deserialize due to AOT and the lack of full
// reflection

[JsonSourceGenerationOptions(WriteIndented = false)]
[JsonSerializable(typeof(object))] // fallback
[JsonSerializable(typeof(ErrorResponse))]
[JsonSerializable(typeof(PingResponse))]
[JsonSerializable(typeof(MeResponse))]
[JsonSerializable(typeof(TokenRequest))]
[JsonSerializable(typeof(TokenResponse))]
[JsonSerializable(typeof(AppConfig))]
[JsonSerializable(typeof(SessionResponse))]
[JsonSerializable(typeof(List<SessionResponse>))]
[JsonSerializable(typeof(MessageResponse))]
[JsonSerializable(typeof(RevokeResponse))]
[JsonSerializable(typeof(PurgeTokensRequest))]
[JsonSerializable(typeof(RefreshRequest))]
[JsonSerializable(typeof(RefreshTokenResponse))]
[JsonSerializable(typeof(List<RefreshTokenResponse>))]
[JsonSerializable(typeof(WhoamiResponse))]
[JsonSerializable(typeof(CreateRoleRequest))]
[JsonSerializable(typeof(AssignRoleRequest))]
[JsonSerializable(typeof(CreatePermissionRequest))]
[JsonSerializable(typeof(AssignPermissionRequest))]
[JsonSerializable(typeof(CheckAccessRequest))]
[JsonSerializable(typeof(AccessCheckResponse))]
[JsonSerializable(typeof(List<string>))]
[JsonSerializable(typeof(OidcDiscoveryResponse))]
[JsonSerializable(typeof(JwksResponse))]
[JsonSerializable(typeof(ClientObject))]
[JsonSerializable(typeof(List<ClientObject>))]
[JsonSerializable(typeof(ScopeObject))]
[JsonSerializable(typeof(List<ScopeObject>))]
[JsonSerializable(typeof(AssignScopesRequest))]
[JsonSerializable(typeof(CreateClientRequest))]
[JsonSerializable(typeof(CreateUserRequest))]
[JsonSerializable(typeof(UserObject))]
[JsonSerializable(typeof(List<UserObject>))]
[JsonSerializable(typeof(AuditLogResponse))]
[JsonSerializable(typeof(List<AuditLogResponse>))]
[JsonSerializable(typeof(PurgeAuditLogRequest))]
[JsonSerializable(typeof(ResetPasswordRequest))]
[JsonSerializable(typeof(RoleObject))]
[JsonSerializable(typeof(List<RoleObject>))]
[JsonSerializable(typeof(PermissionObject))]
[JsonSerializable(typeof(List<PermissionObject>))]
[JsonSerializable(typeof(TokenIntrospectionRequest))]
[JsonSerializable(typeof(Dictionary<string, object>))]
[JsonSerializable(typeof(bool))]
[JsonSerializable(typeof(int))]
[JsonSerializable(typeof(long))]
[JsonSerializable(typeof(string))]
[JsonSerializable(typeof(double))]
[JsonSerializable(typeof(DateTime))]
[JsonSerializable(typeof(string))]
[JsonSerializable(typeof(string[]))]
[JsonSerializable(typeof(object[]))]
[JsonSerializable(typeof(TotpQrRequest))]
[JsonSerializable(typeof(TotpQrResponse))]
[JsonSerializable(typeof(VerifyPasswordRequest))]
[JsonSerializable(typeof(VerifyPasswordResponse))]
[JsonSerializable(typeof(VerifyTotpRequest))]
[JsonSerializable(typeof(VersionResponse))]
[JsonSerializable(typeof(RoleDto))]
[JsonSerializable(typeof(List<RoleDto>))]
[JsonSerializable(typeof(RoleAssignmentDto))]
[JsonSerializable(typeof(PermissionDto))]
[JsonSerializable(typeof(List<PermissionDto>))]
[JsonSerializable(typeof(PermissionAssignmentDto))]
[JsonSerializable(typeof(ScopeDto))]
[JsonSerializable(typeof(List<ScopeDto>))]
[JsonSerializable(typeof(ScopeAssignmentDto))]
[JsonSerializable(typeof(ClientRedirectUriObject))]
[JsonSerializable(typeof(List<ClientRedirectUriObject>))]
public partial class MicroauthJsonContext : JsonSerializerContext
{
}
