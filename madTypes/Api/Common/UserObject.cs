using System.Text.Json.Serialization;
namespace madTypes.Api.Common;

public class UserObject
{
    [JsonPropertyName("id")]
    public required string Id { get; set; }
    [JsonPropertyName("username")]
    public required string Username { get; set; }
    [JsonPropertyName("email")]
    public required string Email { get; set; }
    [JsonPropertyName("created_at")]
    public required DateTime CreatedAt { get; set; }
    [JsonPropertyName("lockout_until")]
    public DateTime? LockoutUntil { get; set; } = null;
    [JsonPropertyName("is_active")]
    public bool IsActive { get; set; }
}
