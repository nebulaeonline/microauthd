using System.Text;

namespace microauthd.Common;

public static class AuthHelpers
{
    /// <summary>
    /// Attempts to parse the Authorization header using HTTP Basic scheme.
    /// </summary>
    /// <param name="authorization">Raw Authorization header</param>
    /// <param name="clientId">Output client identifier</param>
    /// <param name="clientSecret">Output client secret</param>
    /// <returns>True if parsing succeeded and values are valid, otherwise false.</returns>
    public static bool TryParseBasicAuth(string? authorization, out string clientId, out string clientSecret)
    {
        clientId = string.Empty;
        clientSecret = string.Empty;

        if (string.IsNullOrWhiteSpace(authorization) || !authorization.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
            return false;

        try
        {
            var encoded = authorization["Basic ".Length..].Trim();
            var raw = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));

            var split = raw.IndexOf(':');
            if (split <= 0 || split == raw.Length - 1)
                return false;

            clientId = raw[..split];
            clientSecret = raw[(split + 1)..];
            return true;
        }
        catch
        {
            return false;
        }
    }
}
