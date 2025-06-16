namespace microauthd.Api.Requests
{
    public sealed class AssignScopesRequest
    {
        public List<string> ScopeIds { get; init; } = new();
    }
}
