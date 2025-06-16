namespace microauthd.Api.Responses;

public sealed class RevokeResponse
{
    public string Jti { get; init; } = string.Empty;
    public string Status { get; init; } = "unknown"; // revoked, already_revoked, expired, not_found
    public string Message { get; init; } = string.Empty;
}
