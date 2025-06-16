namespace madTypes.Api.Responses;

public sealed class TokenResponse
{
    public string AccessToken { get; init; } = string.Empty;
    public string TokenType { get; init; } = "bearer";
    public int ExpiresIn { get; init; }
    public string? Jti { get; init; }
    public string? RefreshToken { get; init; }
}
