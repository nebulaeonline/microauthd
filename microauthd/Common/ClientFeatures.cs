using System.ComponentModel;

namespace microauthd.Common;

public static class ClientFeatures
{
    public enum Flags
    {
        EnableTotp = 0,
        TotpIssuer = 1,
    }

    public record FeatureFlagMetadata(ClientFeatures.Flags Flag, string FlagString, string Description);

    private readonly static Dictionary<Flags, string> _map = new()
    {
        { Flags.EnableTotp, "ENABLE_TOTP" },
        { Flags.TotpIssuer, "TOTP_ISSUER" }
    };

    private readonly static Dictionary<Flags, string> _descriptions = new()
    {
        { Flags.EnableTotp, "Enable TOTP authentication" },
        { Flags.TotpIssuer, "Issuer for TOTP apps" }
    };

    public static string GetFlagString(Flags flag) =>
        _map.TryGetValue(flag, out var val) ? val : throw new ArgumentOutOfRangeException(nameof(flag));

    public static string GetFlagDescription(Flags flag) =>
        _descriptions.TryGetValue(flag, out var desc) ? desc : throw new ArgumentOutOfRangeException(nameof(flag));

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
                Description: kvp.Value
            )
        );
}
