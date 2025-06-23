using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;

using madClient.Common;

namespace madClient;

public abstract class BaseClient
{
    protected readonly HttpClient _http;
    protected readonly JsonSerializerContext _ctx;

    protected BaseClient(HttpClient http, JsonSerializerContext? ctx = null)
    {
        _http = http;
        _ctx = ctx ?? MadClientJsonContext.Default;
    }

    protected void SetAuthHeader(string token)
    {
        _http.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
    }

    protected async Task<T> GetAsync<T>(string url, bool allowNotFound = false)
    {
        var response = await _http.GetAsync(url);
        if (allowNotFound && response.StatusCode == System.Net.HttpStatusCode.NotFound)
            return default!;
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync(_ctx.GetTypeInfo<T>()))!;
    }

    protected async Task<T> PostAsync<T>(string url, object? body)
    {
        var content = JsonContent.Create(body, _ctx.GetTypeInfo(body!.GetType()));
        var response = await _http.PostAsync(url, content);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync(_ctx.GetTypeInfo<T>()))!;
    }

    protected async Task<T> PostFormAsync<T>(string url, Dictionary<string, string> formFields)
    {
        var content = new FormUrlEncodedContent(formFields);
        var response = await _http.PostAsync(url, content);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync(_ctx.GetTypeInfo<T>()))!;
    }

    protected async Task<T> PutAsync<T>(string url, object? body)
    {
        var content = JsonContent.Create(body, _ctx.GetTypeInfo(body!.GetType()));
        var response = await _http.PutAsync(url, content);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync(_ctx.GetTypeInfo<T>()))!;
    }

    protected async Task<T> DeleteAsync<T>(string url)
    {
        var response = await _http.DeleteAsync(url);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync(_ctx.GetTypeInfo<T>()))!;
    }

    protected async Task<HttpResponseMessage> PostRawAsync(string url, object? body)
    {
        var json = JsonSerializer.Serialize(body, body?.GetType() ?? typeof(object), _ctx.Options);
        var content = new StringContent(json, System.Text.Encoding.UTF8, "application/json");
        var response = await _http.PostAsync(url, content);
        return response;
    }
}
