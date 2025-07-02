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

        var result = await context.AuthenticateAsync();

        string? accessToken = null;
        string? refreshToken = null;

        if (result?.Properties?.Items != null)
        {
            result.Properties.Items.TryGetValue("access_token", out accessToken);
            result.Properties.Items.TryGetValue("refresh_token", out refreshToken);
        }

        if (string.IsNullOrWhiteSpace(accessToken) || string.IsNullOrWhiteSpace(refreshToken))
        {
            await _next(context);
            return;
        }

        // Parse JWT to check expiration
        JwtSecurityToken jwt;
        try
        {
            jwt = new JwtSecurityTokenHandler().ReadToken(accessToken) as JwtSecurityToken;
        }
        catch
        {
            await _next(context); return;
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

        if (options.EnableDebugLogging)
            Console.WriteLine($"[madAuthClient] Access token expires in {timeLeft.TotalSeconds:F0} seconds");

        await _next(context);
    }
}
