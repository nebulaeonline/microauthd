namespace madTypes.Api.Requests;

public sealed class PurgeTokensRequest
{
    public int OlderThanSeconds { get; init; } = 86400;
    public bool PurgeExpired { get; init; } = true;
    public bool PurgeRevoked { get; init; } = false;
}
