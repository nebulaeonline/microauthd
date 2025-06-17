using System.Text.Json.Serialization;
namespace madTypes.Api.Responses;

public class UserResponse
{
    [JsonPropertyName("id")]
    public required string Id { get; set; }
    [JsonPropertyName("username")]
    public required string Username { get; set; }
    [JsonPropertyName("email")]
    public required string Email { get; set; }
    [JsonPropertyName("created_at")]
    public required string CreatedAt { get; set; }
    [JsonPropertyName("is_active")]
    public bool IsActive { get; set; }
}
