using microauthd.Config;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Security.Claims;

public abstract class BasePageModel : PageModel
{
    protected AppConfig Config => HttpContext.RequestServices.GetRequiredService<AppConfig>();
    protected string? UserId => User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    protected string? IpAddress => HttpContext.Connection.RemoteIpAddress?.ToString();
    protected string? UserAgent => HttpContext.Request.Headers["User-Agent"].FirstOrDefault();

    public override void OnPageHandlerExecuting(Microsoft.AspNetCore.Mvc.Filters.PageHandlerExecutingContext context)
    {
        // Only check expiration if authenticated
        if (User.Identity?.IsAuthenticated != true)
        {
            base.OnPageHandlerExecuting(context);
            return;
        }

        var expClaim = User.FindFirst("exp")?.Value;
        if (long.TryParse(expClaim, out var expUnix))
        {
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (now >= expUnix)
            {
                // Token expired — sign out and redirect
                HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme).Wait();
                context.Result = new RedirectToPageResult("/Login");
                return;
            }
        }

        base.OnPageHandlerExecuting(context);
    }
}