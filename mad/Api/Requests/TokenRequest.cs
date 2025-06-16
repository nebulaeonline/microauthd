namespace mad.Api.Requests;

public sealed class TokenRequest
{
    public string Username { get; init; } = string.Empty;
    public string Password { get; init; } = string.Empty;
    public string ClientIdentifier { get; init; } = string.Empty;
}
