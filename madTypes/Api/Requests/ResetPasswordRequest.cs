using System.Text.Json.Serialization;

namespace madTypes.Api.Requests;

public class ResetPasswordRequest
{
    [JsonPropertyName("new_password")]
    public required string NewPassword { get; set; }
}
