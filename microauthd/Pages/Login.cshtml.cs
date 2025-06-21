using madTypes.Api.Requests;
using madTypes.Api.Responses;
using microauthd.Config;
using microauthd.Data;
using microauthd.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Security.Claims;
using Microsoft.IdentityModel.JsonWebTokens;

namespace microauthd.Pages;

public class LoginModel : PageModel
{
    private readonly AppConfig _config;

    public LoginModel(AppConfig config)
    {
        _config = config;
    }

    [BindProperty] public string? Username { get; set; }
    [BindProperty] public string? Password { get; set; }
    [BindProperty] public string? ClientId { get; set; } = "madui";
    public string? ErrorMessage { get; set; }

    public void OnGet() { }

    public async Task<IActionResult> OnPostAsync()
    {
        if (string.IsNullOrWhiteSpace(Username) || string.IsNullOrWhiteSpace(Password))
        {
            ErrorMessage = "Username and password are required.";
            return Page();
        }

        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var ua = Request.Headers["User-Agent"].FirstOrDefault() ?? "unknown";

        var tokenResult = AuthService.IssueAdminToken(new TokenRequest
        {
            Username = Username!,
            Password = Password!,
            ClientIdentifier = ClientId ?? "madui"
        }, _config, ip, ua);

        if (!tokenResult.Success)
        {
            ErrorMessage = tokenResult.Error ?? "Login failed.";
            return Page();
        }

        // Get the expiration time from the token result
        var now = DateTimeOffset.UtcNow;
        var exp = now.AddSeconds(tokenResult.Value!.ExpiresIn);

        // Re-fetch user and claims to create session
        var user = UserStore.GetUserByUsername(Username!);
        if (user == null)
        {
            ErrorMessage = "User not found.";
            return Page();
        }

        var claims = AuthStore.GetUserClaims(user.Id);
        claims.Insert(0, new Claim(JwtRegisteredClaimNames.Sub, user.Id));
        if (!string.IsNullOrWhiteSpace(user.Email))
            claims.Add(new Claim(JwtRegisteredClaimNames.Email, user.Email));
        claims.Add(new Claim("username", user.Username));
        claims.Add(new Claim("exp", exp.ToUnixTimeSeconds().ToString()));

        // Add raw token as a claim
        claims.Add(new Claim("access_token", tokenResult.Value!.AccessToken));

        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme, JwtRegisteredClaimNames.Sub, "role");
        var principal = new ClaimsPrincipal(identity);

        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

        return RedirectToPage("/Dashboard");
    }
}
