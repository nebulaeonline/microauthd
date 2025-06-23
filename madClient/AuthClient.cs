using madClient.Common;
using madTypes.Api.Responses;
using System.Net.Http.Headers;
using System.Net.Http.Json;

namespace madClient;

public class AuthClient : BaseClient
{
    private string? _accessToken;
    private string? _refreshToken;

    public string? AccessToken => _accessToken;
    public string? RefreshToken => _refreshToken;

    public AuthClient(HttpClient http) : base(http) { }

    public static async Task<AuthClient> LoginPasswordAsync(string baseUrl, string username, string password, string clientId = "app")
    {
        var form = new Dictionary<string, string>
        {
            { "grant_type", "password" },
            { "username", username },
            { "password", password },
            { "client_id", clientId }
        };

        var http = new HttpClient { BaseAddress = new Uri(baseUrl.TrimEnd('/')) };
        var client = new AuthClient(http);

        var token = await client.PostFormAsync<TokenResponse>("/token", form);
        if (token == null)
            throw new InvalidOperationException("Failed to parse token response");

        client._accessToken = token.AccessToken;
        client._refreshToken = token.RefreshToken;
        client.SetAuthHeader(token.AccessToken);

        return client;
    }

    public async Task<MeResponse> GetMeAsync()
    {
        return await GetAsync<MeResponse>("/me");
    }

    public async Task<MessageResponse> RevokeAsync(string? token = null)
    {
        var form = new Dictionary<string, string>
        {
            { "token", token ?? _accessToken ?? throw new InvalidOperationException("No token available") }
        };

        return await PostFormAsync<MessageResponse>("/revoke", form);
    }

    public async Task RefreshAsync()
    {
        if (_refreshToken == null)
            throw new InvalidOperationException("No refresh token available");

        var form = new Dictionary<string, string>
        {
            { "grant_type", "refresh_token" },
            { "refresh_token", _refreshToken }
        };

        var token = await PostFormAsync<TokenResponse>("/token", form);
        if (token == null)
            throw new InvalidOperationException("Refresh failed: invalid response");

        _accessToken = token.AccessToken;
        _refreshToken = token.RefreshToken;
        SetAuthHeader(_accessToken);
    }
}

