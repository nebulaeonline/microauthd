using System.Text.Json.Serialization;

namespace madTypes.Api.Common;

public class PkceCode
{
    [JsonPropertyName("code")]
    public string Code { get; set; } = default!;
    [JsonPropertyName("client_id")]
    public string ClientIdentifier { get; set; } = default!;
    [JsonPropertyName("redirect_uri")]
    public string RedirectUri { get; set; } = default!;
    [JsonPropertyName("code_challenge")]
    public string CodeChallenge { get; set; } = default!;
    [JsonPropertyName("code_challenge_method")]
    public string CodeChallengeMethod { get; set; } = "plain";
    [JsonPropertyName("expires_at")]
    public DateTime ExpiresAt { get; set; }
    [JsonPropertyName("is_used")]
    public bool IsUsed { get; set; }
    [JsonPropertyName("user_id")]
    public string UserId { get; set; } = default!;
    [JsonPropertyName("jti")]
    public string? Jti { get; set; }
    [JsonPropertyName("nonce")]
    public string? Nonce { get; set; }
    [JsonPropertyName("scope")]
    public string? Scope { get; set; }
    [JsonPropertyName("login_method")]
    public string? LoginMethod { get; set; }
    [JsonPropertyName("max_age")]
    public int? MaxAge { get; set; }
}
