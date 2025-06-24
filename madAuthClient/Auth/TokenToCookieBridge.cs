using madTypes.Api.Responses;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using System.Security.Claims;

namespace madAuthClient.Auth;

public static class TokenToCookieBridge
{
    public static async Task SignInAsync(HttpContext httpContext, TokenResponse token, IEnumerable<Claim> claims, string? cookieScheme = null)
    {
        var scheme = cookieScheme ?? CookieAuthenticationDefaults.AuthenticationScheme;

        var identity = new ClaimsIdentity(claims, scheme, ClaimTypes.NameIdentifier, ClaimTypes.Role);
        var principal = new ClaimsPrincipal(identity);

        var expiresUtc = DateTimeOffset.UtcNow.AddSeconds(token.ExpiresIn);

        var authProps = new AuthenticationProperties
        {
            IsPersistent = true,
            ExpiresUtc = expiresUtc
        };

        await httpContext.SignInAsync(scheme, principal, authProps);
    }

    public static async Task SignOutAsync(HttpContext httpContext, string? cookieScheme = null)
    {
        var scheme = cookieScheme ?? CookieAuthenticationDefaults.AuthenticationScheme;
        await httpContext.SignOutAsync(scheme);
    }
}

