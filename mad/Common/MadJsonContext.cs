using System.Text.Json.Serialization;

using mad.Api.Responses;
using mad.Api.Requests;
    
namespace mad.Common;

[JsonSourceGenerationOptions(WriteIndented = false)]
[JsonSerializable(typeof(object))] // fallback
[JsonSerializable(typeof(List<string>))]
[JsonSerializable(typeof(ErrorResponse))]
[JsonSerializable(typeof(TokenResponse))]
[JsonSerializable(typeof(TokenRequest))]
[JsonSerializable(typeof(CreateUserRequest))]
[JsonSerializable(typeof(UserResponse))]
[JsonSerializable(typeof(List<UserResponse>))]
[JsonSerializable(typeof(CreateRoleRequest))]
[JsonSerializable(typeof(AssignRoleRequest))]
[JsonSerializable(typeof(ScopeResponse))]
[JsonSerializable(typeof(List<ScopeResponse>))]
[JsonSerializable(typeof(AssignScopesRequest))]
[JsonSerializable(typeof(CreatePermissionRequest))]
[JsonSerializable(typeof(AssignPermissionRequest))]
[JsonSerializable(typeof(CheckAccessRequest))]
[JsonSerializable(typeof(AccessCheckResponse))]
[JsonSerializable(typeof(CreateClientRequest))]
[JsonSerializable(typeof(ClientResponse))]
[JsonSerializable(typeof(List<ClientResponse>))]
[JsonSerializable(typeof(RoleResponse))]
[JsonSerializable(typeof(List<RoleResponse>))]
[JsonSerializable(typeof(PermissionResponse))]
[JsonSerializable(typeof(List<PermissionResponse>))]
public partial class MadJsonContext : JsonSerializerContext { }
