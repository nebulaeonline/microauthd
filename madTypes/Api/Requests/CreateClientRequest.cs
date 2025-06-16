namespace madTypes.Api.Requests;

public sealed class CreateClientRequest
{
    public string ClientId { get; init; } = string.Empty;
    public string ClientSecret { get; init; } = string.Empty;
    public string? DisplayName { get; init; }
}
