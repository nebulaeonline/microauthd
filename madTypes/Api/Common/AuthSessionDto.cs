using System.Text.Json.Serialization;

namespace madTypes.Api.Common;

public class AuthSessionDto
{
    [JsonPropertyName("jti")]
    public string Jti { get; set; } = default!;

    [JsonPropertyName("client_id")]
    public string ClientId { get; set; } = default!;
    [JsonPropertyName("user_id")]
    public string? UserId { get; set; }
    [JsonPropertyName("redirect_uri")]
    public string RedirectUri { get; set; } = default!;
    [JsonPropertyName("totp_required")]
    public bool TotpRequired { get; set; } = false;

    [JsonPropertyName("nonce")]
    public string? Nonce { get; set; } // This can be nullable if it's not required.

    [JsonPropertyName("scope")]
    public string? Scope { get; set; }

    [JsonPropertyName("state")]
    public string? State { get; set; }
    [JsonPropertyName("code_challenge")]
    public string CodeChallenge { get; set; } = default!;
    [JsonPropertyName("code_challenge_method")]
    public string CodeChallengeMethod { get; set; } = default!;

    [JsonPropertyName("created_at_utc")]
    public DateTime CreatedAtUtc { get; set; }

    [JsonPropertyName("expires_at_utc")]
    public DateTime ExpiresAtUtc { get; set; }
}
