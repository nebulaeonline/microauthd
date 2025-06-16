using System.Security.Claims;

namespace microauthd.Common;

public static class ClaimsPrincipalExtensions
{
    public static string? GetUserId(this ClaimsPrincipal user)
    {
        return user.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? user.FindFirst("sub")?.Value;
    }

    public static bool HasScope(this ClaimsPrincipal user, string requiredScope)
    {
        var scopeClaim = user.FindFirst("scope")?.Value;
        return scopeClaim?.Split(' ').Contains(requiredScope) == true;
    }
}
