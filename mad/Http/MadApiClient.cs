using madTypes.Api.Requests;
using madTypes.Api.Responses;
using mad.Common;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

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
        Console.WriteLine("DEBUG: Starting admin login to " + $"{BaseUrl}/token");
        Console.WriteLine($"DEBUG: username = {username}");

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

        req.Headers.Add("Accept", "application/json");

        var res = await _http.SendAsync(req);
        var body = await res.Content.ReadAsStringAsync();

        Console.WriteLine("DEBUG: Response code = " + (int)res.StatusCode);
        Console.WriteLine("DEBUG: Response body = " + body);

        if (!res.IsSuccessStatusCode)
            return false;

        var token = JsonSerializer.Deserialize(body, MadJsonContext.Default.TokenResponse);

        if (token == null || string.IsNullOrWhiteSpace(token.AccessToken))
            return false;

        Token = token.AccessToken;
        _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", Token);
        return true;
    }


    public async Task<HttpResponseMessage> CreateUser(CreateUserRequest request)
    {
        var content = JsonContent.Create(
            request,
            MadJsonContext.Default.CreateUserRequest
        );

        return await _http.PostAsync($"{BaseUrl}/users", content);
    }

    public async Task<List<UserResponse>?> ListUsers()
    {
        var res = await _http.GetAsync($"{BaseUrl}/users");
        if (!res.IsSuccessStatusCode)
            return null;

        return await res.Content.ReadFromJsonAsync(
            MadJsonContext.Default.ListUserResponse
        );
    }

    public async Task<bool> DeleteUser(string userId)
    {
        var res = await _http.DeleteAsync($"{BaseUrl}/users/{userId}");
        return res.IsSuccessStatusCode;
    }

    public async Task<bool> ActivateUser(string userId)
    {
        var res = await _http.PostAsync($"{BaseUrl}/users/{userId}/activate", content: null);
        return res.IsSuccessStatusCode;
    }
    public async Task<string> CreateRole(CreateRoleRequest request)
    {
        var content = JsonContent.Create(
            request,
            MadJsonContext.Default.CreateRoleRequest
        );

        var res = await _http.PostAsync($"{BaseUrl}/roles", content);
        return await res.Content.ReadAsStringAsync();
    }

    public async Task<List<RoleResponse>?> ListRoles()
    {
        var res = await _http.GetAsync($"{BaseUrl}/roles");
        if (!res.IsSuccessStatusCode)
            return null;

        return await res.Content.ReadFromJsonAsync(
            MadJsonContext.Default.ListRoleResponse
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

    public async Task<string> CreateScope(ScopeResponse scope)
    {
        var content = JsonContent.Create(scope, MadJsonContext.Default.ScopeResponse);
        var res = await _http.PostAsync($"{BaseUrl}/scopes", content);
        return await res.Content.ReadAsStringAsync();
    }

    public async Task<List<ScopeResponse>> ListScopes()
    {
        var res = await _http.GetAsync($"{BaseUrl}/scopes");
        if (!res.IsSuccessStatusCode)
            return new();

        return await res.Content.ReadFromJsonAsync(MadJsonContext.Default.ListScopeResponse)
               ?? new();
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

    public async Task<List<ScopeResponse>> ListScopesForUser(string userId)
    {
        var res = await _http.GetAsync($"{BaseUrl}/users/{userId}/scopes");
        if (!res.IsSuccessStatusCode)
            return new();

        return await res.Content.ReadFromJsonAsync(MadJsonContext.Default.ListScopeResponse)
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

    public async Task<List<ScopeResponse>> ListScopesForClient(string clientId)
    {
        var res = await _http.GetAsync($"{BaseUrl}/clients/{clientId}/scopes");
        if (!res.IsSuccessStatusCode)
            return new();

        return await res.Content.ReadFromJsonAsync(MadJsonContext.Default.ListScopeResponse)
               ?? new();
    }

    public async Task<bool> RemoveScopeFromClient(string clientId, string scopeId)
    {
        var res = await _http.DeleteAsync($"{BaseUrl}/clients/{clientId}/scopes/{scopeId}");
        return res.IsSuccessStatusCode;
    }

    public async Task<string> CreatePermission(CreatePermissionRequest request)
    {
        var content = JsonContent.Create(request, MadJsonContext.Default.CreatePermissionRequest);
        var res = await _http.PostAsync($"{BaseUrl}/permissions", content);
        return await res.Content.ReadAsStringAsync();
    }

    public async Task<List<PermissionResponse>> ListPermissions()
    {
        var res = await _http.GetAsync($"{BaseUrl}/permissions");
        if (!res.IsSuccessStatusCode)
            return new();

        return await res.Content.ReadFromJsonAsync(MadJsonContext.Default.ListPermissionResponse)
               ?? new();
    }

    public async Task<bool> DeletePermission(string permissionId)
    {
        var res = await _http.DeleteAsync($"{BaseUrl}/permissions/{permissionId}");
        return res.IsSuccessStatusCode;
    }

    public async Task<bool> AssignPermissionsToRole(string roleId, List<string> permissionIds)
    {
        var body = new AssignPermissionRequest { PermissionIds = permissionIds };
        var content = JsonContent.Create(body, MadJsonContext.Default.AssignPermissionRequest);
        var res = await _http.PostAsync($"{BaseUrl}/roles/{roleId}/permissions", content);
        return res.IsSuccessStatusCode;
    }

    public async Task<bool> RemovePermissionFromRole(string roleId, string permissionId)
    {
        var res = await _http.DeleteAsync($"{BaseUrl}/roles/{roleId}/permissions/{permissionId}");
        return res.IsSuccessStatusCode;
    }

    public async Task<List<string>> ListPermissionsForRole(string roleId)
    {
        var res = await _http.GetAsync($"{BaseUrl}/roles/{roleId}/permissions");
        if (!res.IsSuccessStatusCode)
            return new();

        return await res.Content.ReadFromJsonAsync(MadJsonContext.Default.ListString)
               ?? new();
    }

    public async Task<List<string>> ListPermissionsForUser(string userId)
    {
        var res = await _http.GetAsync($"{BaseUrl}/permissions/user/{userId}");
        if (!res.IsSuccessStatusCode)
            return new();

        return await res.Content.ReadFromJsonAsync(MadJsonContext.Default.ListString)
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

    public async Task<string> CreateClient(CreateClientRequest request)
    {
        var content = JsonContent.Create(request, MadJsonContext.Default.CreateClientRequest);
        var res = await _http.PostAsync($"{BaseUrl}/clients", content);
        return await res.Content.ReadAsStringAsync();
    }

    public async Task<List<ClientResponse>> ListClients()
    {
        var res = await _http.GetAsync($"{BaseUrl}/clients");
        if (!res.IsSuccessStatusCode)
            return new();

        return await res.Content.ReadFromJsonAsync(MadJsonContext.Default.ListClientResponse)
               ?? new();
    }

    public async Task<bool> DeleteClient(string clientId)
    {
        var res = await _http.DeleteAsync($"{BaseUrl}/clients/{clientId}");
        return res.IsSuccessStatusCode;
    }

    public void SetToken(string token)
    {
        Token = token;
        _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
    }
}
