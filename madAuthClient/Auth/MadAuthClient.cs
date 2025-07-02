using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using madAuthClient.Options;
using madTypes.Api.Requests;
using madTypes.Api.Responses;

namespace madAuthClient.Auth;

public class MadAuthClient
{
    private readonly HttpClient _http;
    private readonly MadAuthOptions _options;

    public MadAuthClient(HttpClient httpClient, MadAuthOptions options)
    {
        _http = httpClient;
        _options = options;
    }

    public async Task<TokenResponse?> LoginAsync(string username, string password, CancellationToken cancellationToken = default)
    {
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = username,
            ["password"] = password,
            ["client_id"] = _options.ClientId,
            ["client_secret"] = _options.ClientSecret
        };

        var response = await _http.PostAsync("/token", new FormUrlEncodedContent(form), cancellationToken);
        if (!response.IsSuccessStatusCode)
            return null;

        var token = await response.Content.ReadFromJsonAsync<TokenResponse>(cancellationToken: cancellationToken);
        if (_options.EnableDebugLogging)
            Console.WriteLine($"[madAuthClient] Token: {JsonSerializer.Serialize(token)}");

        return token;
    }

    public async Task<TokenResponse?> RefreshAsync(string refreshToken, CancellationToken cancellationToken = default)
    {
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = refreshToken,
            ["client_id"] = _options.ClientId,
            ["client_secret"] = _options.ClientSecret
        };

        var response = await _http.PostAsync("/token", new FormUrlEncodedContent(form), cancellationToken);
        if (!response.IsSuccessStatusCode)
            return null;

        return await response.Content.ReadFromJsonAsync<TokenResponse>(cancellationToken: cancellationToken);
    }

    public async Task<bool> RevokeAsync(string token, CancellationToken cancellationToken = default)
    {
        var form = new Dictionary<string, string>
        {
            ["token"] = token,
            ["client_id"] = _options.ClientId,
            ["client_secret"] = _options.ClientSecret
        };

        var response = await _http.PostAsync("/revoke", new FormUrlEncodedContent(form), cancellationToken);
        return response.IsSuccessStatusCode;
    }

    public async Task<MeResponse?> GetUserInfoAsync(string accessToken, CancellationToken cancellationToken = default)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "/me");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        var response = await _http.SendAsync(request, cancellationToken);
        if (!response.IsSuccessStatusCode)
            return null;

        return await response.Content.ReadFromJsonAsync<MeResponse>(cancellationToken: cancellationToken);
    }

    public async Task<TokenResponse?> ExchangeAuthorizationCodeAsync(string code, string redirectUri, string codeVerifier, CancellationToken ct = default)
    {
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = _options.ClientId,
            ["client_secret"] = _options.ClientSecret,
            ["code"] = code,
            ["redirect_uri"] = redirectUri,
            ["code_verifier"] = codeVerifier
        };

        var response = await _http.PostAsync("/token", new FormUrlEncodedContent(form), ct);
        if (!response.IsSuccessStatusCode)
            return null;

        return await response.Content.ReadFromJsonAsync<TokenResponse>(cancellationToken: ct);
    }
}
