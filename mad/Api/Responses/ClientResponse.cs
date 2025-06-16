namespace mad.Api.Responses;

public sealed class ClientResponse
{
    public string Id { get; init; } = string.Empty;
    public string ClientId { get; init; } = string.Empty;
    public string DisplayName { get; init; } = string.Empty;
    public bool IsActive { get; init; }
    public string CreatedAt { get; init; } = string.Empty;
}
