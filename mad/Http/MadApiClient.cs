using madTypes.Api.Requests;
using madTypes.Api.Responses;
using mad.Common;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using madTypes.Api.Common;

namespace mad.Http;

internal class MadApiClient
{
    private readonly HttpClient _http;

    public string BaseUrl { get; }
    public string? Token { get; private set; }

    public MadApiClient(string baseUrl)
    {
        BaseUrl = baseUrl.TrimEnd('/');
        _http = new HttpClient();
    }

    public MadApiClient(string baseUrl, string token)
        : this(baseUrl)
    {
        SetToken(token);
    }

    public async Task<bool> Authenticate(string username, string password, string clientId)
    {
        var payload = new Dictionary<string, string>
        {
            { "username", username },
            { "password", password },
            { "client_id", clientId }
        };

        var content = new FormUrlEncodedContent(payload);

        var req = new HttpRequestMessage(HttpMethod.Post, $"{BaseUrl}/token")
        {
            Content = content
        };

        try
        {
            req.Headers.Add("Accept", "application/json");

            var res = await _http.SendAsync(req);
            var body = await res.Content.ReadAsStringAsync();

            if (!res.IsSuccessStatusCode)
                return false;

            var token = JsonSerializer.Deserialize(body, MadJsonContext.Default.TokenResponse);

            if (token == null || string.IsNullOrWhiteSpace(token.AccessToken))
                return false;

            Token = token.AccessToken;
            _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", Token);
            return true;
        }
        catch
        {
            return false;
        }
    }

    public async Task<UserObject?> CreateUser(CreateUserRequest request)
    {
        var content = JsonContent.Create(
            request,
            MadJsonContext.Default.CreateUserRequest
        );

        var res = await _http.PostAsync($"{BaseUrl}/users", content);
        if (!res.IsSuccessStatusCode)
            return null;

        return await res.Content.ReadFromJsonAsync(
            MadJsonContext.Default.UserObject
        );
    }

    public async Task<TotpQrResponse?> GenerateTotpQrCode(TotpQrRequest request)
    {
        var content = JsonContent.Create(
            request,
            MadJsonContext.Default.TotpQrRequest
        );

        var res = await _http.PostAsync($"{BaseUrl}/users/{request.UserId}/totp/generate", content);
        if (!res.IsSuccessStatusCode)
            return null;

        return await res.Content.ReadFromJsonAsync(
            MadJsonContext.Default.TotpQrResponse
        );
    }

    public async Task<MessageResponse?> VerifyTotpCode(VerifyTotpRequest request)
    {
        var content = JsonContent.Create(
            request,
            MadJsonContext.Default.VerifyTotpRequest
        );

        var res = await _http.PostAsync($"{BaseUrl}/users/totp/verify", content);
        if (!res.IsSuccessStatusCode)
            return null;

        return await res.Content.ReadFromJsonAsync(
            MadJsonContext.Default.MessageResponse
        );
    }

    public async Task<MessageResponse?> DisableTotpForUser(string userId)
    {
        var res = await _http.PostAsync($"{BaseUrl}/users/{userId}/disable-totp", null);
        if (!res.IsSuccessStatusCode)
            return null;

        return await res.Content.ReadFromJsonAsync(MadJsonContext.Default.MessageResponse);
    }

    public async Task<UserObject?> UpdateUser(string id, UserObject updated)
    {
        var content = JsonContent.Create(updated, MadJsonContext.Default.UserObject);
        var res = await _http.PutAsync($"{BaseUrl}/users/{id}", content);

        if (!res.IsSuccessStatusCode)
            return null;

        return await res.Content.ReadFromJsonAsync(MadJsonContext.Default.UserObject);
    }

    public async Task<MessageResponse?> MarkEmailVerified(string userId)
    {
        var res = await _http.PostAsync($"{BaseUrl}/users/{userId}/verify-email", null);
        return res.IsSuccessStatusCode
            ? await res.Content.ReadFromJsonAsync(MadJsonContext.Default.MessageResponse)
            : null;
    }

    public async Task<MessageResponse?> ResetUserPassword(string userId, string newPassword)
    {
        var req = new ResetPasswordRequest
        {
            NewPassword = newPassword
        };

        var content = JsonContent.Create(req, MadJsonContext.Default.ResetPasswordRequest);

        var res = await _http.PostAsync($"{BaseUrl}/users/{userId}/reset", content);
        if (!res.IsSuccessStatusCode)
            return null;

        return await res.Content.ReadFromJsonAsync(MadJsonContext.Default.MessageResponse);
    }

    public async Task<List<UserObject>?> ListUsers()
    {
        var res = await _http.GetAsync($"{BaseUrl}/users");

        if (!res.IsSuccessStatusCode)
            return null;

        return await res.Content.ReadFromJsonAsync(
            MadJsonContext.Default.ListUserObject
        );
    }

    public async Task<UserObject?> GetUserById(string id)
    {
        var res = await _http.GetAsync($"{BaseUrl}/users/{id}");
        if (!res.IsSuccessStatusCode)
            return null;

        return await res.Content.ReadFromJsonAsync(MadJsonContext.Default.UserObject);
    }

    public async Task<bool> DeactivateUser(string userId)
    {
        var res = await _http.PostAsync($"{BaseUrl}/users/deactivate/{userId}", content: null);
        return res.IsSuccessStatusCode;
    }

    public async Task<bool> DeleteUser(string userId)
    {
        var res = await _http.DeleteAsync($"{BaseUrl}/users/{userId}");
        return res.IsSuccessStatusCode;
    }

    public async Task<MessageResponse?> SetUserLockout(string userId, DateTime until)
    {
        var payload = new SetUserLockoutRequest
        {
            LockoutUntil = until
        };

        var content = JsonContent.Create(payload, MadJsonContext.Default.SetUserLockoutRequest);
        var res = await _http.PostAsync($"{BaseUrl}/users/{userId}/set-lockout", content);

        if (!res.IsSuccessStatusCode)
            return null;

        return await res.Content.ReadFromJsonAsync(MadJsonContext.Default.MessageResponse);
    }

    public async Task<MessageResponse?> ClearUserLockout(string userId)
    {
        var payload = new SetUserLockoutRequest
        {
            LockoutUntil = default // This will be serialized as null
        };

        var content = JsonContent.Create(payload, MadJsonContext.Default.SetUserLockoutRequest);
        var res = await _http.PostAsync($"{BaseUrl}/users/{userId}/set-lockout", content);

        if (!res.IsSuccessStatusCode)
            return null;

        return await res.Content.ReadFromJsonAsync(MadJsonContext.Default.MessageResponse);
    }

    public async Task<bool> ActivateUser(string userId)
    {
        var res = await _http.PostAsync($"{BaseUrl}/users/{userId}/activate", content: null);
        return res.IsSuccessStatusCode;
    }

    public async Task<List<SessionResponse>> ListSessions()
    {
        var res = await _http.GetAsync($"{BaseUrl}/sessions");
        if (!res.IsSuccessStatusCode)
            return new();

        return await res.Content.ReadFromJsonAsync(MadJsonContext.Default.ListSessionResponse)
               ?? new();
    }

    public async Task<Dictionary<string, object>?> IntrospectTokenAsAdmin(string token)
    {
        var req = new Dictionary<string, string>
        {
            ["token"] = token
        };

        var res = await _http.PostAsync($"{BaseUrl}/introspect", new FormUrlEncodedContent(req));
        if (!res.IsSuccessStatusCode)
            return null;

        return await res.Content.ReadFromJsonAsync(MadJsonContext.Default.DictionaryStringObject);
    }

    public async Task<SessionResponse?> GetSessionById(string sessionId)
    {
        var res = await _http.GetAsync($"{BaseUrl}/sessions/{sessionId}");
        if (!res.IsSuccessStatusCode)
            return null;

        return await res.Content.ReadFromJsonAsync(MadJsonContext.Default.SessionResponse);
    }

    public async Task<List<SessionResponse>> ListSessionsForUser(string userId)
    {
        var res = await _http.GetAsync($"{BaseUrl}/sessions/user/{userId}");
        if (!res.IsSuccessStatusCode)
            return new();

        return await res.Content.ReadFromJsonAsync(MadJsonContext.Default.ListSessionResponse)
               ?? new();
    }

    public async Task<bool> RevokeSession(string jti)
    {
        var res = await _http.DeleteAsync($"{BaseUrl}/sessions/{jti}");
        return res.IsSuccessStatusCode;
    }

    public async Task<bool> PurgeSessions(int olderThanSeconds, bool purgeExpired, bool purgeRevoked)
    {
        var payload = new PurgeTokensRequest(olderThanSeconds, purgeExpired, purgeRevoked);
        var content = JsonContent.Create(payload, MadJsonContext.Default.PurgeTokensRequest);
        var res = await _http.PostAsync($"{BaseUrl}/sessions/purge", content);
        return res.IsSuccessStatusCode;
    }

    public async Task<List<RefreshTokenResponse>> ListRefreshTokens()
    {
        var res = await _http.GetAsync($"{BaseUrl}/refresh-tokens");
        if (!res.IsSuccessStatusCode)
            return new();

        return await res.Content.ReadFromJsonAsync(MadJsonContext.Default.ListRefreshTokenResponse) ?? new();
    }

    public async Task<List<RefreshTokenResponse>> ListRefreshTokensForUser(string userId)
    {
        var res = await _http.GetAsync($"{BaseUrl}/refresh-tokens/user/{userId}");
        if (!res.IsSuccessStatusCode)
            return new();

        return await res.Content.ReadFromJsonAsync(MadJsonContext.Default.ListRefreshTokenResponse) ?? new();
    }

    public async Task<RefreshTokenResponse?> GetRefreshToken(string id)
    {
        var res = await _http.GetAsync($"{BaseUrl}/refresh-tokens/{id}");
        if (!res.IsSuccessStatusCode)
            return null;

        return await res.Content.ReadFromJsonAsync(MadJsonContext.Default.RefreshTokenResponse);
    }

    public async Task<bool> PurgeRefreshTokens(int olderThanSeconds, bool purgeExpired, bool purgeRevoked)
    {
        var payload = new PurgeTokensRequest(olderThanSeconds, purgeExpired, purgeRevoked);
        var content = JsonContent.Create(payload, MadJsonContext.Default.PurgeTokensRequest);
        var res = await _http.PostAsync($"{BaseUrl}/refresh-tokens/purge", content);
        return res.IsSuccessStatusCode;
    }

    public async Task<RoleObject?> CreateRole(CreateRoleRequest request)
    {
        var content = JsonContent.Create(
            request,
            MadJsonContext.Default.CreateRoleRequest
        );

        var res = await _http.PostAsync($"{BaseUrl}/roles", content);
        if (!res.IsSuccessStatusCode)
            return null;

        return await res.Content.ReadFromJsonAsync(MadJsonContext.Default.RoleObject);
    }

    public async Task<RoleObject?> UpdateRole(string id, RoleObject updated)
    {
        var content = JsonContent.Create(updated, MadJsonContext.Default.RoleObject);
        var res = await _http.PutAsync($"{BaseUrl}/roles/{id}", content);
        if (!res.IsSuccessStatusCode)
            return null;

        return await res.Content.ReadFromJsonAsync(MadJsonContext.Default.RoleObject);
    }

    public async Task<RoleObject?> GetRoleById(string id)
    {
        var res = await _http.GetAsync($"{BaseUrl}/roles/{id}");
        if (!res.IsSuccessStatusCode)
            return null;

        return await res.Content.ReadFromJsonAsync(MadJsonContext.Default.RoleObject);
    }

    public async Task<List<RoleObject>?> ListRoles()
    {
        var res = await _http.GetAsync($"{BaseUrl}/roles");
        if (!res.IsSuccessStatusCode)
            return null;

        return await res.Content.ReadFromJsonAsync(
            MadJsonContext.Default.ListRoleObject
        );
    }

    public async Task<bool> DeleteRole(string roleId)
    {
        var res = await _http.DeleteAsync($"{BaseUrl}/roles/{roleId}");
        return res.IsSuccessStatusCode;
    }

    public async Task<bool> AssignRole(string userId, string roleId)
    {
        var payload = new AssignRoleRequest
        {
            UserId = userId,
            RoleId = roleId
        };

        var content = JsonContent.Create(
            payload,
            MadJsonContext.Default.AssignRoleRequest
        );

        var res = await _http.PostAsync($"{BaseUrl}/roles/assign", content);
        return res.IsSuccessStatusCode;
    }

    public async Task<bool> UnassignRole(string userId, string roleId)
    {
        var payload = new AssignRoleRequest
        {
            UserId = userId,
            RoleId = roleId
        };

        var content = JsonContent.Create(
            payload,
            MadJsonContext.Default.AssignRoleRequest
        );

        var res = await _http.PostAsync($"{BaseUrl}/roles/unassign", content);
        return res.IsSuccessStatusCode;
    }

    public async Task<ScopeObject?> CreateScope(ScopeObject scope)
    {
        var content = JsonContent.Create(scope, (System.Text.Json.Serialization.Metadata.JsonTypeInfo<ScopeObject>)MadJsonContext.Default.ScopeObject);
        var res = await _http.PostAsync($"{BaseUrl}/scopes", content);

        if (!res.IsSuccessStatusCode)
            return null;

        return await res.Content.ReadFromJsonAsync(MadJsonContext.Default.ScopeObject);
    }

    public async Task<ScopeObject?> UpdateScope(string id, ScopeObject updated)
    {
        var content = JsonContent.Create(updated, MadJsonContext.Default.ScopeObject);
        var res = await _http.PutAsync($"{BaseUrl}/scopes/{id}", content);

        if (!res.IsSuccessStatusCode)
            return null;

        return await res.Content.ReadFromJsonAsync(MadJsonContext.Default.ScopeObject);
    }

    public async Task<List<ScopeObject>> ListScopes()
    {
        var res = await _http.GetAsync($"{BaseUrl}/scopes");
        if (!res.IsSuccessStatusCode)
            return new();

        return await res.Content.ReadFromJsonAsync(MadJsonContext.Default.ListScopeObject)
               ?? new();
    }

    public async Task<ScopeObject?> GetScopeById(string id)
    {
        var res = await _http.GetAsync($"{BaseUrl}/scopes/{id}");
        if (!res.IsSuccessStatusCode)
            return null;

        return await res.Content.ReadFromJsonAsync(MadJsonContext.Default.ScopeObject);
    }

    public async Task<bool> DeleteScope(string scopeId)
    {
        var res = await _http.DeleteAsync($"{BaseUrl}/scopes/{scopeId}");
        return res.IsSuccessStatusCode;
    }

    public async Task<bool> AssignScopesToUser(string userId, List<string> scopeIds)
    {
        var body = new AssignScopesRequest { ScopeIds = scopeIds };
        var content = JsonContent.Create(body, MadJsonContext.Default.AssignScopesRequest);
        var res = await _http.PostAsync($"{BaseUrl}/users/{userId}/scopes", content);
        return res.IsSuccessStatusCode;
    }

    public async Task<List<ScopeObject>> ListScopesForUser(string userId)
    {
        var res = await _http.GetAsync($"{BaseUrl}/users/{userId}/scopes");
        if (!res.IsSuccessStatusCode)
            return new();

        return await res.Content.ReadFromJsonAsync(MadJsonContext.Default.ListScopeObject)
               ?? new();
    }

    public async Task<bool> RemoveScopeFromUser(string userId, string scopeId)
    {
        var res = await _http.DeleteAsync($"{BaseUrl}/users/{userId}/scopes/{scopeId}");
        return res.IsSuccessStatusCode;
    }

    public async Task<bool> AssignScopesToClient(string clientId, List<string> scopeIds)
    {
        var body = new AssignScopesRequest { ScopeIds = scopeIds };
        var content = JsonContent.Create(body, MadJsonContext.Default.AssignScopesRequest);
        var res = await _http.PostAsync($"{BaseUrl}/clients/{clientId}/scopes", content);
        return res.IsSuccessStatusCode;
    }

    public async Task<List<ScopeObject>> ListScopesForClient(string clientId)
    {
        var res = await _http.GetAsync($"{BaseUrl}/clients/{clientId}/scopes");
        if (!res.IsSuccessStatusCode)
            return new();

        return await res.Content.ReadFromJsonAsync(MadJsonContext.Default.ListScopeObject)
               ?? new();
    }

    public async Task<bool> RemoveScopeFromClient(string clientId, string scopeId)
    {
        var res = await _http.DeleteAsync($"{BaseUrl}/clients/{clientId}/scopes/{scopeId}");
        return res.IsSuccessStatusCode;
    }

    public async Task<PermissionObject?> CreatePermission(CreatePermissionRequest request)
    {
        var content = JsonContent.Create(request, MadJsonContext.Default.CreatePermissionRequest);
        var res = await _http.PostAsync($"{BaseUrl}/permissions", content);
        if (!res.IsSuccessStatusCode)
            return null;

        return await res.Content.ReadFromJsonAsync(MadJsonContext.Default.PermissionObject);
    }

    public async Task<PermissionObject?> UpdatePermission(string id, PermissionObject updated)
    {
        var content = JsonContent.Create(updated, MadJsonContext.Default.PermissionObject);
        var res = await _http.PutAsync($"{BaseUrl}/permissions/{id}", content);
        if (!res.IsSuccessStatusCode)
            return null;

        return await res.Content.ReadFromJsonAsync(MadJsonContext.Default.PermissionObject);
    }

    public async Task<List<PermissionObject>> ListPermissions()
    {
        var res = await _http.GetAsync($"{BaseUrl}/permissions");
        if (!res.IsSuccessStatusCode)
            return new();

        return await res.Content.ReadFromJsonAsync(MadJsonContext.Default.ListPermissionObject)
               ?? new();
    }

    public async Task<PermissionObject?> GetPermissionById(string id)
    {
        var res = await _http.GetAsync($"{BaseUrl}/permissions/{id}");
        if (!res.IsSuccessStatusCode)
            return null;

        return await res.Content.ReadFromJsonAsync(MadJsonContext.Default.PermissionObject);
    }

    public async Task<bool> DeletePermission(string permissionId)
    {
        var res = await _http.DeleteAsync($"{BaseUrl}/permissions/{permissionId}");
        return res.IsSuccessStatusCode;
    }

    public async Task<bool> AssignPermissionsToRole(string roleId, string permissionId)
    {
        var body = new AssignPermissionRequest { PermissionId = permissionId };
        var content = JsonContent.Create(body, MadJsonContext.Default.AssignPermissionRequest);
        var res = await _http.PostAsync($"{BaseUrl}/roles/{roleId}/permissions", content);
        return res.IsSuccessStatusCode;
    }

    public async Task<bool> RemovePermissionFromRole(string roleId, string permissionId)
    {
        var res = await _http.DeleteAsync($"{BaseUrl}/roles/{roleId}/permissions/{permissionId}");
        return res.IsSuccessStatusCode;
    }

    public async Task<List<PermissionObject>> ListPermissionsForRole(string roleId)
    {
        var res = await _http.GetAsync($"{BaseUrl}/roles/{roleId}/permissions");
        if (!res.IsSuccessStatusCode)
            return new();

        return await res.Content.ReadFromJsonAsync(MadJsonContext.Default.ListPermissionObject)
               ?? new();
    }

    public async Task<List<PermissionObject>> ListPermissionsForUser(string userId)
    {
        var res = await _http.GetAsync($"{BaseUrl}/permissions/user/{userId}");
        if (!res.IsSuccessStatusCode)
            return new();

        return await res.Content.ReadFromJsonAsync(MadJsonContext.Default.ListPermissionObject)
               ?? new();
    }

    public async Task<bool> CheckAccess(string userId, string permissionId)
    {
        var body = new CheckAccessRequest
        {
            UserId = userId,
            PermissionId = permissionId
        };

        var content = JsonContent.Create(body, MadJsonContext.Default.CheckAccessRequest);
        var res = await _http.PostAsync($"{BaseUrl}/check-access", content);

        if (!res.IsSuccessStatusCode)
            return false;

        var result = await res.Content.ReadFromJsonAsync(MadJsonContext.Default.AccessCheckResponse);
        return result?.Allowed ?? false;
    }

    public async Task<ClientObject?> CreateClient(CreateClientRequest request)
    {
        var content = JsonContent.Create(request, MadJsonContext.Default.CreateClientRequest);
        var res = await _http.PostAsync($"{BaseUrl}/clients", content);
        if (!res.IsSuccessStatusCode)
            return null;

        return await res.Content.ReadFromJsonAsync(MadJsonContext.Default.ClientObject);
    }

    public async Task<ClientObject?> UpdateClient(string id, ClientObject updated)
    {
        var content = JsonContent.Create(updated, MadJsonContext.Default.ClientObject);
        var res = await _http.PutAsync($"{BaseUrl}/clients/{id}", content);

        if (!res.IsSuccessStatusCode)
            return null;

        return await res.Content.ReadFromJsonAsync(MadJsonContext.Default.ClientObject);
    }

    public async Task<List<ClientObject>> ListClients()
    {
        var res = await _http.GetAsync($"{BaseUrl}/clients");
        if (!res.IsSuccessStatusCode)
            return new();

        return await res.Content.ReadFromJsonAsync(MadJsonContext.Default.ListClientObject)
               ?? new();
    }

    public async Task<ClientObject?> GetClientById(string id)
    {
        var res = await _http.GetAsync($"{BaseUrl}/clients/{id}");
        if (!res.IsSuccessStatusCode)
            return null;

        return await res.Content.ReadFromJsonAsync(MadJsonContext.Default.ClientObject);
    }

    public async Task<MessageResponse?> ChangeClientSecret(ChangeClientSecretRequest req)
    {
        var content = JsonContent.Create(req, MadJsonContext.Default.ChangeClientSecretRequest);

        var res = await _http.PostAsync($"{BaseUrl}/clients/secret", content);
        if (!res.IsSuccessStatusCode)
            return null;

        return await res.Content.ReadFromJsonAsync(MadJsonContext.Default.MessageResponse);
    }

    public async Task<bool> DeleteClient(string clientId)
    {
        var res = await _http.DeleteAsync($"{BaseUrl}/clients/{clientId}");
        return res.IsSuccessStatusCode;
    }

    public async Task<ClientRedirectUriObject?> AddRedirectUri(string clientGuid, string uri)
    {
        var payload = new { uri };
        var content = JsonContent.Create(payload, MadJsonContext.Default.Object);

        var res = await _http.PostAsync($"{BaseUrl}/clients/{clientGuid}/redirect-uris", content);
        if (!res.IsSuccessStatusCode)
            return null;

        return await res.Content.ReadFromJsonAsync(MadJsonContext.Default.ClientRedirectUriObject);
    }

    public async Task<List<ClientRedirectUriObject>> ListRedirectUris(string clientGuid)
    {
        var res = await _http.GetAsync($"{BaseUrl}/clients/{clientGuid}/redirect-uris");
        if (!res.IsSuccessStatusCode)
            return new();

        return await res.Content.ReadFromJsonAsync(MadJsonContext.Default.ListClientRedirectUriObject)
               ?? new();
    }

    public async Task<bool> DeleteRedirectUri(string redirectUriId)
    {
        var res = await _http.DeleteAsync($"{BaseUrl}/clients/redirect-uris/{redirectUriId}");
        return res.IsSuccessStatusCode;
    }

    public void SetToken(string token)
    {
        Token = token;
        _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
    }

    public async Task<List<AuditLogResponse>> ListAuditLogs(string? userId, string? action, int? limit)
    {
        var query = new List<string>();
        if (!string.IsNullOrWhiteSpace(userId))
            query.Add($"userId={Uri.EscapeDataString(userId)}");
        if (!string.IsNullOrWhiteSpace(action))
            query.Add($"action={Uri.EscapeDataString(action)}");
        if (limit is not null)
            query.Add($"limit={limit}");

        var url = $"{BaseUrl}/audit-logs";
        if (query.Count > 0)
            url += "?" + string.Join("&", query);

        var res = await _http.GetAsync(url);
        if (!res.IsSuccessStatusCode)
            return new();

        return await res.Content.ReadFromJsonAsync(MadJsonContext.Default.ListAuditLogResponse)
               ?? new();
    }

    public async Task<AuditLogResponse?> GetAuditLogById(string id)
    {
        var res = await _http.GetAsync($"{BaseUrl}/audit-logs/{id}");
        if (!res.IsSuccessStatusCode)
            return null;

        return await res.Content.ReadFromJsonAsync(MadJsonContext.Default.AuditLogResponse);
    }

    public async Task<bool> PurgeAuditLogs(int days)
    {
        var payload = new PurgeAuditLogRequest(days);
        var content = JsonContent.Create(payload, MadJsonContext.Default.PurgeAuditLogRequest);

        var res = await _http.PostAsync($"{BaseUrl}/audit-logs/purge", content);
        return res.IsSuccessStatusCode;
    }
}
