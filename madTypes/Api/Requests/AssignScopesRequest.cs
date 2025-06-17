using System.Text.Json.Serialization;

namespace madTypes.Api.Requests
{
    public sealed class AssignScopesRequest
    {
        [JsonPropertyName("scope_ids")]
        public List<string> ScopeIds { get; init; } = new();
    }
}
