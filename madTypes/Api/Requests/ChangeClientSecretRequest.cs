using System.Text.Json.Serialization;

namespace madTypes.Api.Requests
{
    public record ChangeClientSecretRequest(
        [property: JsonPropertyName("client_id")] string ClientId,
        [property: JsonPropertyName("new_secret")] string? NewSecret
    );
}
