using microauthd.Config;
using microauthd.Data;
using madTypes.Common;

namespace microauthd.Tokens;

public static class TokenPolicy
{
    /// <summary>
    /// Determines the lifetime of an access token for a given client.
    /// </summary>
    /// <param name="config">The application configuration containing default token expiration settings.</param>
    /// <param name="clientId">The unique identifier of the client for which the token lifetime is being calculated.</param>
    /// <param name="maxAge">An optional maximum age, in seconds, to constrain the token lifetime. If specified, the token lifetime will be
    /// the lesser of this value and the configured lifetime.</param>
    /// <returns>The access token lifetime, in seconds, for the specified client. If <paramref name="maxAge"/> is provided, the
    /// returned value will not exceed <paramref name="maxAge"/>.</returns>
    public static int GetAccessTokenLifetime(AppConfig config, string clientId, int? maxAge = null)
    {
        var configuredTtl = ClientFeaturesStore.GetFeatureOptionInt(clientId, ClientFeatures.Flags.TokenExpiration)
            ?? config.TokenExpiration;

        return maxAge.HasValue
            ? Math.Min(configuredTtl, maxAge.Value)
            : configuredTtl;
    }

    /// <summary>
    /// Determines the refresh token lifetime for a given client.
    /// </summary>
    /// <remarks>The refresh token lifetime is determined based on the client's specific configuration, if
    /// available, or falls back to the default value specified in <paramref name="config"/>.</remarks>
    /// <param name="config">The application configuration containing default settings for refresh token expiration.</param>
    /// <param name="clientId">The unique identifier of the client for which the refresh token lifetime is being calculated.</param>
    /// <param name="maxAge">An optional maximum age, in seconds, to constrain the refresh token lifetime. If specified, the resulting
    /// lifetime will be the lesser of this value and the configured lifetime.</param>
    /// <returns>The refresh token lifetime, in seconds, for the specified client. If <paramref name="maxAge"/> is provided, the
    /// returned value will not exceed <paramref name="maxAge"/>.</returns>
    public static int GetRefreshTokenLifetime(AppConfig config, string clientId, int? maxAge = null)
    {
        var configuredTtl = ClientFeaturesStore.GetFeatureOptionInt(clientId, ClientFeatures.Flags.RefreshTokenExpiration)
            ?? config.RefreshTokenExpiration;

        return maxAge.HasValue
            ? Math.Min(configuredTtl, maxAge.Value)
            : configuredTtl;
    }
}
