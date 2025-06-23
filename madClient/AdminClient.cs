using madClient.Common;
using madTypes.Api.Common;
using madTypes.Api.Requests;
using madTypes.Api.Responses;
using madTypes.Common;
using System.Net.Http;
using System.Net.Http.Json;

namespace madClient
{
    public class AdminClient : BaseClient
    {
        public AdminClient(HttpClient httpClient)
        : base(httpClient)
        {
        }

        public async Task<UserObject> CreateUserAsync(CreateUserRequest request)
        {
            return await PostAsync<UserObject>("/users", request);
        }

        public async Task<List<UserObject>> ListUsersAsync()
        {
            return await GetAsync<List<UserObject>>("/users");
        }

        public async Task<UserObject?> GetUserByIdAsync(string id)
        {
            return await GetAsync<UserObject>($"/users/{id}", allowNotFound: true);
        }

        public async Task<string?> GetUserIdByUsernameAsync(string username)
        {
            return await GetAsync<string>($"/users/id-by-name/{username}", allowNotFound: true);
        }

        public async Task<UserObject> UpdateUserAsync(string id, UserObject user)
        {
            return await PutAsync<UserObject>($"/users/{id}", user);
        }

        public async Task<MessageResponse> DeactivateUserAsync(string id)
        {
            return await PostAsync<MessageResponse>($"/users/deactivate/{id}", null);
        }

        public async Task<MessageResponse> ActivateUserAsync(string id)
        {
            return await PostAsync<MessageResponse>($"/users/{id}/activate", null);
        }

        public async Task<MessageResponse> DeleteUserAsync(string id)
        {
            return await DeleteAsync<MessageResponse>($"/users/{id}");
        }

        public async Task<MessageResponse> ResetUserPasswordAsync(string id, string newPassword)
        {
            var req = new ResetPasswordRequest { NewPassword = newPassword };
            return await PostAsync<MessageResponse>($"/users/{id}/reset", req);
        }

        public async Task<bool> VerifyPasswordAsync(string username, string password)
        {
            var req = new VerifyPasswordRequest { Username = username, Password = password };
            var response = await PostRawAsync($"/users/verify-password", req);
            return response.StatusCode == System.Net.HttpStatusCode.OK;
        }

        public async Task<MessageResponse> DisableTotpAsync(string userId)
        {
            return await PostAsync<MessageResponse>($"/users/{userId}/disable-totp", null);
        }

        public async Task<TotpQrResponse> GenerateTotpAsync(string userId, string outputPath)
        {
            var req = new TotpQrRequest { UserId = userId, QrOutputPath = outputPath };
            return await PostAsync<TotpQrResponse>($"/users/{userId}/totp/generate", req);
        }

        public async Task<bool> VerifyTotpCodeAsync(string userId, string code)
        {
            var req = new VerifyTotpRequest { UserId = userId, Code = code };
            var response = await PostRawAsync($"/users/totp/verify", req);
            return response.StatusCode == System.Net.HttpStatusCode.OK;
        }

        // GET /sessions
        public async Task<List<SessionResponse>> ListSessionsAsync()
        {
            return await GetAsync<List<SessionResponse>>("/sessions") ?? new();
        }

        // GET /sessions/{jti}
        public async Task<SessionResponse?> GetSessionAsync(string jti)
        {
            return await GetAsync<SessionResponse>($"/sessions/{jti}");
        }

        // DELETE /sessions/{jti}
        public async Task<MessageResponse> DeleteSessionAsync(string jti)
        {
            var response = await _http.DeleteAsync($"/sessions/{jti}");
            response.EnsureSuccessStatusCode();
            return (await response.Content.ReadFromJsonAsync(MadClientJsonContext.Default.MessageResponse))!;
        }

        // GET /sessions/user/{userId}
        public async Task<List<SessionResponse>> ListSessionsForUserAsync(string userId)
        {
            return await GetAsync<List<SessionResponse>>($"/sessions/user/{userId}") ?? new();
        }

        // POST /sessions/purge
        public async Task<MessageResponse> PurgeSessionsAsync(PurgeTokensRequest req)
        {
            return await PostAsync<MessageResponse>("/sessions/purge", req);
        }

        // GET /roles
        public async Task<List<RoleObject>> ListRolesAsync()
        {
            return await GetAsync<List<RoleObject>>("/roles") ?? new();
        }

        // GET /roles/{id}
        public async Task<RoleObject?> GetRoleByIdAsync(string id)
        {
            return await GetAsync<RoleObject>($"/roles/{id}");
        }

        // GET /roles/id-by-name/{name}
        public async Task<string?> GetRoleIdByNameAsync(string name)
        {
            return await GetAsync<string>($"/roles/id-by-name/{name}");
        }

        // POST /roles
        public async Task<RoleObject> CreateRoleAsync(CreateRoleRequest req)
        {
            return await PostAsync<RoleObject>("/roles", req);
        }

        // PUT /roles/{id}
        public async Task<RoleObject> UpdateRoleAsync(string id, RoleObject updated)
        {
            return await PutAsync<RoleObject>($"/roles/{id}", updated);
        }

        // DELETE /roles/{id}
        public async Task<MessageResponse> DeleteRoleAsync(string roleId)
        {
            var response = await _http.DeleteAsync($"/roles/{roleId}");
            response.EnsureSuccessStatusCode();
            return (await response.Content.ReadFromJsonAsync(MadClientJsonContext.Default.MessageResponse))!;
        }

        // POST /roles/assign
        public async Task<MessageResponse> AssignRoleToUserAsync(AssignRoleRequest req)
        {
            return await PostAsync<MessageResponse>("/roles/assign", req);
        }

        // POST /roles/unassign
        public async Task<MessageResponse> UnassignRoleFromUserAsync(AssignRoleRequest req)
        {
            return await PostAsync<MessageResponse>("/roles/unassign", req);
        }

        // GET /roles/user/{userId}
        public async Task<List<string>> ListRolesForUserAsync(string userId)
        {
            return await GetAsync<List<string>>($"/roles/user/{userId}") ?? new();
        }

        // GET /users/{userId}/roles?all={bool}
        public async Task<List<RoleDto>> GetUserRolesAsync(string userId, bool includeAll = false)
        {
            var url = $"/users/{userId}/roles?all={includeAll.ToString().ToLower()}";
            return await GetAsync<List<RoleDto>>(url) ?? new();
        }

        // PUT /users/{userId}/roles
        public async Task<MessageResponse> ReplaceUserRolesAsync(string userId, List<RoleDto> roles)
        {
            var dto = new RoleAssignmentDto
            {
                UserId = userId,
                Roles = roles
            };

            return await PutAsync<MessageResponse>($"/users/{userId}/roles", dto);
        }

        // GET /roles/{roleId}/permissions
        public async Task<List<PermissionObject>> GetPermissionsForRoleAsync(string roleId)
        {
            return await GetAsync<List<PermissionObject>>($"/roles/{roleId}/permissions") ?? new();
        }

        // GET /permissions/retrieve/{roleId}
        public async Task<List<PermissionDto>> GetAssignedPermissionDtosAsync(string roleId)
        {
            return await GetAsync<List<PermissionDto>>($"/permissions/retrieve/{roleId}") ?? new();
        }

        // GET /permissions
        public async Task<List<PermissionObject>> ListPermissionsAsync()
        {
            return await GetAsync<List<PermissionObject>>("/permissions") ?? new();
        }

        // GET /permissions/{id}
        public async Task<PermissionObject?> GetPermissionByIdAsync(string id)
        {
            return await GetAsync<PermissionObject>($"/permissions/{id}");
        }

        // GET /permissions/id-by-name/{name}
        public async Task<string?> GetPermissionIdByNameAsync(string name)
        {
            return await GetAsync<string>($"/permissions/id-by-name/{name}");
        }

        // POST /permissions
        public async Task<PermissionObject> CreatePermissionAsync(CreatePermissionRequest req)
        {
            return await PostAsync<PermissionObject>("/permissions", req);
        }

        // PUT /permissions/{id}
        public async Task<PermissionObject> UpdatePermissionAsync(string id, PermissionObject updated)
        {
            return await PutAsync<PermissionObject>($"/permissions/{id}", updated);
        }

        // DELETE /permissions/{id}
        public async Task<MessageResponse> DeletePermissionAsync(string id)
        {
            var response = await _http.DeleteAsync($"/permissions/{id}");
            response.EnsureSuccessStatusCode();
            return (await response.Content.ReadFromJsonAsync(MadClientJsonContext.Default.MessageResponse))!;
        }

        // GET /permissions/retrieve/all
        public async Task<List<PermissionDto>> GetAllPermissionDtosAsync()
        {
            return await GetAsync<List<PermissionDto>>("/permissions/retrieve/all") ?? new();
        }

        // POST /roles/{roleId}/permissions
        public async Task<MessageResponse> AssignPermissionToRoleAsync(string roleId, AssignPermissionRequest req)
        {
            return await PostAsync<MessageResponse>($"/roles/{roleId}/permissions", req);
        }

        // DELETE /roles/{roleId}/permissions/{permissionId}
        public async Task<MessageResponse> RemovePermissionFromRoleAsync(string roleId, string permissionId)
        {
            var response = await _http.DeleteAsync($"/roles/{roleId}/permissions/{permissionId}");
            response.EnsureSuccessStatusCode();
            return (await response.Content.ReadFromJsonAsync(MadClientJsonContext.Default.MessageResponse))!;
        }

        // GET /permissions/user/{userId}
        public async Task<List<PermissionObject>> GetPermissionsForUserAsync(string userId)
        {
            return await GetAsync<List<PermissionObject>>($"/permissions/user/{userId}") ?? new();
        }

        // POST /check-access
        public async Task<bool> CheckAccessAsync(CheckAccessRequest req)
        {
            var result = await PostAsync<AccessCheckResponse>("/check-access", req);
            return result.Allowed;
        }

        public async Task<ClientObject> CreateClientAsync(CreateClientRequest req)
        {
            return await PostAsync<ClientObject>("/clients", req);
        }

        public async Task<ClientObject?> GetClientByIdAsync(string id)
        {
            return await GetAsync<ClientObject>($"/clients/{id}");
        }

        public async Task<List<ClientObject>> ListClientsAsync()
        {
            return await GetAsync<List<ClientObject>>("/clients");
        }

        public async Task<ClientObject> UpdateClientAsync(string id, ClientObject updated)
        {
            return await PutAsync<ClientObject>($"/clients/{id}", updated);
        }

        public async Task<MessageResponse> DeleteClientAsync(string id)
        {
            return await DeleteAsync<MessageResponse>($"/clients/{id}");
        }

        public async Task<string?> GetClientIdByIdentifierAsync(string clientId)
        {
            var result = await GetAsync<ApiResult<string>>($"/clients/id-by-name/{clientId}", allowNotFound: true);
            return result?.Value;
        }

        public async Task<MessageResponse> AddScopesToClientAsync(string clientId, AssignScopesRequest req)
        {
            return await PostAsync<MessageResponse>($"/clients/{clientId}/scopes", req);
        }

        public async Task<List<ScopeObject>> GetScopesForClientAsync(string clientId)
        {
            return await GetAsync<List<ScopeObject>>($"/clients/{clientId}/scopes");
        }

        public async Task<MessageResponse> RemoveScopeFromClientAsync(string clientId, string scopeId)
        {
            return await DeleteAsync<MessageResponse>($"/clients/{clientId}/scopes/{scopeId}");
        }

        // SCOPES

        public async Task<ScopeObject> CreateScopeAsync(ScopeObject scope)
        {
            return await PostAsync<ScopeObject>("/scopes", scope);
        }

        public async Task<ScopeObject> UpdateScopeAsync(string scopeId, ScopeObject updated)
        {
            return await PutAsync<ScopeObject>($"/scopes/{scopeId}", updated);
        }

        public async Task<List<ScopeObject>> ListScopesAsync()
        {
            return await GetAsync<List<ScopeObject>>("/scopes");
        }

        public async Task<ScopeObject> GetScopeByIdAsync(string scopeId)
        {
            return await GetAsync<ScopeObject>($"/scopes/{scopeId}");
        }

        public async Task<string> GetScopeIdByNameAsync(string name)
        {
            var result = await GetAsync<ApiResult<string>>($"/scopes/id-by-name/{name}");
            return result.Value!;
        }

        public async Task<MessageResponse> DeleteScopeAsync(string scopeId)
        {
            return await DeleteAsync<MessageResponse>($"/scopes/{scopeId}");
        }

        public async Task<MessageResponse> AssignScopesToUserAsync(string userId, AssignScopesRequest req)
        {
            return await PostAsync<MessageResponse>($"/users/{userId}/scopes", req);
        }

        public async Task<List<ScopeObject>> ListScopesForUserAsync(string userId)
        {
            return await GetAsync<List<ScopeObject>>($"/users/{userId}/scopes");
        }

        public async Task<MessageResponse> RemoveScopeFromUserAsync(string userId, string scopeId)
        {
            return await DeleteAsync<MessageResponse>($"/users/{userId}/scopes/{scopeId}");
        }

        public async Task<MessageResponse> AssignScopesToClientAsync(string clientId, AssignScopesRequest req)
        {
            return await PostAsync<MessageResponse>($"/clients/{clientId}/scopes", req);
        }


        public async Task<List<ScopeObject>> ListScopesForClientAsync(string clientId)
        {
            return await GetAsync<List<ScopeObject>>($"/clients/{clientId}/scopes");
        }
    }
}
