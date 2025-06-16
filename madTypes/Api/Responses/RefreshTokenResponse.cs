namespace madTypes.Api.Responses;

public sealed class RefreshTokenResponse
{
    public string Id { get; init; } = string.Empty;
    public string UserId { get; init; } = string.Empty;
    public string SessionId { get; init; } = string.Empty;
    public string ClientIdentifier { get; init; } = string.Empty;
    public DateTime IssuedAt { get; init; }
    public DateTime ExpiresAt { get; init; }
    public bool IsRevoked { get; init; }
}
