namespace microauthd.Api.Requests;

public sealed class RefreshRequest
{
    public string RefreshToken { get; init; } = string.Empty;
}
