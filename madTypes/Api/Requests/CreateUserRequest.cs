using System.Text.Json.Serialization;

namespace madTypes.Api.Requests;

public class CreateUserRequest
{
    [JsonPropertyName("username")]
    public required string Username { get; set; }
    [JsonPropertyName("email")]
    public required string Email { get; set; }
    [JsonPropertyName("password")]
    public required string Password { get; set; }
}
