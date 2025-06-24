using madAuthClient.Auth;
using madAuthClient.Options;
using madTypes.Api.Responses;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;
using System.Security.Claims;

namespace madRazorExample.Pages;

public class LoginModel : PageModel
{
    private readonly MadAuthClient _client;
    private readonly MadAuthOptions _options;

    public LoginModel(MadAuthClient client, IOptions<MadAuthOptions> options)
    {
        _client = client;
        _options = options.Value;
    }

    [BindProperty] public string Username { get; set; } = string.Empty;
    [BindProperty] public string Password { get; set; } = string.Empty;
    public string? ErrorMessage { get; set; }

    public void OnGet() { }

    public async Task<IActionResult> OnPostAsync()
    {
        if (string.IsNullOrWhiteSpace(Username) || string.IsNullOrWhiteSpace(Password))
        {
            ErrorMessage = "Username and password are required.";
            return Page();
        }

        var token = await _client.LoginAsync(Username, Password);
        if (token is null)
        {
            ErrorMessage = "Invalid credentials.";
            return Page();
        }

        var userInfo = await _client.GetUserInfoAsync(token.AccessToken);
        var claims = ClaimsBuilder.FromToken(token, userInfo);

        await TokenToCookieBridge.SignInAsync(HttpContext, token, claims);

        return RedirectToPage("/SecurePage");
    }
}

