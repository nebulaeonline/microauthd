namespace madTypes.Api.Responses;

public sealed class SessionResponse
{
    public string Id { get; init; } = string.Empty;
    public string UserId { get; init; } = string.Empty;
    public string ClientIdentifier { get; init; } = string.Empty;
    public DateTime IssuedAt { get; init; }
    public DateTime ExpiresAt { get; init; }
    public bool IsRevoked { get; init; }
    public string TokenUse { get; init; } = "auth";
}
