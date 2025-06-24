using madAuthClient.Auth;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Security.Claims;

namespace madRazorExample.Pages;

public class LogoutModel : PageModel
{
    private readonly MadAuthClient _client;

    public LogoutModel(MadAuthClient client)
    {
        _client = client;
    }

    public async Task<IActionResult> OnGet()
    {
        var accessToken = User.FindFirst("access_token")?.Value;

        await TokenToCookieBridge.SignOutAsync(HttpContext);

        // Revoke token if available
        if (!string.IsNullOrWhiteSpace(accessToken))
        {
            await _client.RevokeAsync(accessToken);
        }

        return RedirectToPage("/Login");
    }
}
