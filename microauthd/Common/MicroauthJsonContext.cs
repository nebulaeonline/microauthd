using System.Text.Json.Serialization;

using microauthd.Config;
using madTypes.Api.Requests;
using madTypes.Api.Responses;

namespace microauthd.Common;

// Our JsonSerializerContext must be annotated
// with all the types we intend to serialize &
// deserialize due to AOT and the lack of full
// reflection

[JsonSourceGenerationOptions(
    WriteIndented = false,
    PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower)]
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
[JsonSerializable(typeof(ClientResponse))]
[JsonSerializable(typeof(List<ClientResponse>))]
[JsonSerializable(typeof(ScopeResponse))]
[JsonSerializable(typeof(List<ScopeResponse>))]
[JsonSerializable(typeof(AssignScopesRequest))]
[JsonSerializable(typeof(CreateClientRequest))]
[JsonSerializable(typeof(CreateUserRequest))]
[JsonSerializable(typeof(UserResponse))]
[JsonSerializable(typeof(List<UserResponse>))]
[JsonSerializable(typeof(AuditLogResponse))]
[JsonSerializable(typeof(List<AuditLogResponse>))]
[JsonSerializable(typeof(PurgeAuditLogRequest))]
[JsonSerializable(typeof(ResetPasswordRequest))]
[JsonSerializable(typeof(RoleResponse))]
[JsonSerializable(typeof(List<RoleResponse>))]
[JsonSerializable(typeof(PermissionResponse))]
[JsonSerializable(typeof(List<PermissionResponse>))]
[JsonSerializable(typeof(TokenIntrospectionRequest))]
public partial class MicroauthJsonContext : JsonSerializerContext
{
}
