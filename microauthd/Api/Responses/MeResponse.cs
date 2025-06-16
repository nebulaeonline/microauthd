namespace microauthd.Api.Responses;

public record MeResponse(
    string Subject,
    string? Email,
    List<string> Roles
);
