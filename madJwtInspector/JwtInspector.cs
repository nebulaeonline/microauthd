using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace madJwtInspector;

public record JwtIntrospectionResult(
    Dictionary<string, JsonElement> Header,
    Dictionary<string, JsonElement> Payload,
    string? Signature,
    bool IsValidFormat,
    string? ErrorMessage
);

public static class JwtInspector
{
    public static JwtIntrospectionResult Decode(string token)
    {
        if (string.IsNullOrWhiteSpace(token))
            return new JwtIntrospectionResult(new(), new(), null, false, "Empty token");

        var parts = token.Split('.');
        if (parts.Length != 3)
            return new JwtIntrospectionResult(new(), new(), null, false, "Token must have 3 parts");

        try
        {
            var headerJson = DecodePart(parts[0]);
            var payloadJson = DecodePart(parts[1]);
            var header = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(headerJson, JwtJsonContext.Default.DictionaryStringJsonElement) ?? new();
            var payload = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(payloadJson, JwtJsonContext.Default.DictionaryStringJsonElement) ?? new();

            // add readable (utc) times
            foreach (var key in new[] { "exp", "iat", "nbf" })
            {
                if (payload.TryGetValue(key, out var val) &&
                    val.ValueKind == JsonValueKind.Number &&
                    val.TryGetInt64(out var seconds))
                {
                    var utc = DateTimeOffset.FromUnixTimeSeconds(seconds).UtcDateTime;
                    payload[key] = JsonDocument.Parse($"\"{utc:yyyy-MM-dd HH:mm:ss 'UTC'}\"").RootElement;
                }
            }

            return new JwtIntrospectionResult(header, payload, parts[2], true, null);
        }
        catch (Exception ex)
        {
            return new JwtIntrospectionResult(new(), new(), null, false, ex.Message);
        }
    }

    private static string DecodePart(string base64Url)
    {
        var padded = ((base64Url.Length) % 4) switch
        {
            2 => base64Url + "==",
            3 => base64Url + "=",
            _ => base64Url
        };

        var bytes = Convert.FromBase64String(padded.Replace('-', '+').Replace('_', '/'));
        return System.Text.Encoding.UTF8.GetString(bytes);
    }
}
