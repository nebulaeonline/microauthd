using System.Text.Json.Serialization;

namespace madTypes.Api.Responses;

public class CreatedResponse
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = default!;
    [JsonPropertyName("message")]
    public string Message { get; set; } = default!;
}
