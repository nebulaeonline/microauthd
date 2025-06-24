using madAuthClient.Options;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace madAuthClient.Auth;

public class RefreshTokenMiddleware
{
    private readonly RequestDelegate _next;

    public RefreshTokenMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context, MadAuthClient client, IOptions<MadAuthOptions> optionsAccessor)
    {
        var user = context.User;
        var options = optionsAccessor.Value;

        if (user?.Identity?.IsAuthenticated != true)
        {
            await _next(context);
            return;
        }

        var accessToken = user.FindFirst("access_token")?.Value;
        var refreshToken = user.FindFirst("refresh_token")?.Value;

        if (string.IsNullOrWhiteSpace(accessToken) || string.IsNullOrWhiteSpace(refreshToken))
        {
            await _next(context);
            return;
        }

        // Parse JWT to check expiration
        var jwt = new JwtSecurityTokenHandler().ReadToken(accessToken) as JwtSecurityToken;
        if (jwt == null || !jwt.Payload.Exp.HasValue)
        {
            await _next(context);
            return;
        }

        var expiry = DateTimeOffset.FromUnixTimeSeconds(jwt.Payload.Exp.Value);
        var timeLeft = expiry - DateTimeOffset.UtcNow;

        if (timeLeft.TotalSeconds <= options.AutoRefreshSkewSeconds)
        {
            var newToken = await client.RefreshAsync(refreshToken);
            if (newToken is not null)
            {
                var newClaims = ClaimsBuilder.FromToken(newToken);
                await TokenToCookieBridge.SignInAsync(context, newToken, newClaims);
            }
        }

        await _next(context);
    }
}
