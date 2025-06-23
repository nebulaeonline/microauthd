using Microsoft.AspNetCore.Http;

namespace microauthd.Common;

public class RateLimitMiddleware
{
    private readonly RequestDelegate _next;
    private readonly string _tag;

    public RateLimitMiddleware(RequestDelegate next, string tag)
    {
        _next = next;
        _tag = tag;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var ip = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";

        if (!RateLimiter.IsAllowed(ip, _tag))
        {
            context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
            await context.Response.WriteAsync("Too Many Requests");
            return;
        }

        await _next(context);
    }
}
