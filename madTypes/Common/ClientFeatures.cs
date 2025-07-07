using System.ComponentModel;

namespace madTypes.Common;

public static class ClientFeatures
{
    public enum Flags
    {
        EnableTotp = 0,
        TotpIssuer = 1,
        TokenExpiration = 2,
        RefreshTokenExpiration = 3,
        SessionBasedAuth = 4,
        SessionBasedMaxAge = 5,
    }

    public record FeatureFlagMetadata(ClientFeatures.Flags Flag, string FlagString, string Description, bool HasExtendedOptions);

    private readonly static Dictionary<Flags, string> _map = new()
    {
        { Flags.EnableTotp, "ENABLE_TOTP" },
        { Flags.TotpIssuer, "TOTP_ISSUER" },
        { Flags.TokenExpiration, "TOKEN_EXPIRATION" },
        { Flags.RefreshTokenExpiration, "REFRESH_TOKEN_EXPIRATION" },
        { Flags.SessionBasedAuth, "SESSION_BASED_AUTH" },
        { Flags.SessionBasedMaxAge, "SESSION_BASED_MAX_AGE" }
    };

    private readonly static Dictionary<Flags, string> _descriptions = new()
    {
        { Flags.EnableTotp, "Enable TOTP authentication" },
        { Flags.TotpIssuer, "Issuer for TOTP apps" },
        { Flags.TokenExpiration, "Expiration time for access tokens (in seconds)" },
        { Flags.RefreshTokenExpiration, "Expiration time for refresh tokens (in seconds)" },
        { Flags.SessionBasedAuth, "Enable session-based authentication (single-token per session, built-in login pages)" },
        { Flags.SessionBasedMaxAge, "Maximum age for session-based authentication (in seconds)" }
    };

    private readonly static Dictionary<Flags, bool> _hasExtendedOptions = new()
    {
        { Flags.EnableTotp, false },
        { Flags.TotpIssuer, true },
        { Flags.TokenExpiration, true },
        { Flags.RefreshTokenExpiration, true },
        { Flags.SessionBasedAuth, false },
        { Flags.SessionBasedMaxAge, true   }
    };

    public static string GetFlagString(Flags flag) =>
        _map.TryGetValue(flag, out var val) ? val : throw new ArgumentOutOfRangeException(nameof(flag));

    public static string GetFlagDescription(Flags flag) =>
        _descriptions.TryGetValue(flag, out var desc) ? desc : throw new ArgumentOutOfRangeException(nameof(flag));

    public static bool GetHasExtendedOptions(Flags flag) =>
        _hasExtendedOptions.TryGetValue(flag, out var hasOptions) ? hasOptions : throw new ArgumentOutOfRangeException(nameof(flag));

    public static Flags? Parse(string input)
    {
        foreach (var kvp in _map)
        {
            if (kvp.Value.Equals(input.Trim(), StringComparison.OrdinalIgnoreCase))
                return kvp.Key;
        }
        return null;
    }

    public static IEnumerable<string> AllFlags => _map.Values;

    public static IEnumerable<KeyValuePair<ClientFeatures.Flags, string>> AllDescriptions => _descriptions;

    public static IEnumerable<FeatureFlagMetadata> AllMetadata =>
        _descriptions.Select(kvp =>
            new FeatureFlagMetadata(
                Flag: kvp.Key,
                FlagString: GetFlagString(kvp.Key),
                Description: kvp.Value,
                HasExtendedOptions: GetHasExtendedOptions(kvp.Key)
            )
        );
}
