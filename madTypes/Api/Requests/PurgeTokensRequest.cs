using System.Text.Json.Serialization;
namespace madTypes.Api.Requests;

public sealed class PurgeTokensRequest
{
    [JsonPropertyName("older_than_seconds")]
    public int OlderThanSeconds { get; init; } = 86400;
    [JsonPropertyName("purge_expired")]
    public bool PurgeExpired { get; init; } = true;
    [JsonPropertyName("purge_revoked")]
    public bool PurgeRevoked { get; init; } = false;

    public PurgeTokensRequest(int olderThanSeconds = 86400, bool purgeExpired = true, bool purgeRevoked = false)
    {
        OlderThanSeconds = olderThanSeconds;
        PurgeExpired = purgeExpired;
        PurgeRevoked = purgeRevoked;
    }
}
