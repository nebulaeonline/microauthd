// File: Options/MadAuthOptions.cs
namespace madAuthClient.Options;

public class MadAuthOptions
{
    /// <summary>
    /// Base URL of the microauthd AUTH server (e.g. "https://auth.myapp.com")
    /// </summary>
    public required string AuthServerUrl { get; set; }

    /// <summary>
    /// The client identifier to use when requesting tokens
    /// </summary>
    public required string ClientId { get; set; }

    /// <summary>
    /// The client secret used for token and refresh authentication
    /// </summary>
    public required string ClientSecret { get; set; }

    /// <summary>
    /// The name of the authentication cookie used to persist the user session
    /// </summary>
    public string CookieName { get; set; } = "mad.auth";

    /// <summary>
    /// Number of seconds before expiry when a token should be refreshed (if middleware is enabled)
    /// </summary>
    public int AutoRefreshSkewSeconds { get; set; } = 60;

    /// <summary>
    /// Optional: Enable logging of raw token responses for debugging
    /// </summary>
    public bool EnableDebugLogging { get; set; } = false;
}
