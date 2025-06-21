using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using microauthd.Services;
using Microsoft.AspNetCore.Authorization;
using microauthd.Common;
using microauthd.Config;
using System.ComponentModel.DataAnnotations;

namespace microauthd.Pages.Admin.Users;

[Authorize(Roles = Constants.MadAdmin)]
public class CreateModel : BasePageModel
{
    [BindProperty]
    [Required(ErrorMessage = "Username is required")]
    [StringLength(100, MinimumLength = 3, ErrorMessage = "Username must be at least 3 characters long.")]
    public string Username { get; set; } = string.Empty;

    [BindProperty]
    [EmailAddress(ErrorMessage = "Invalid email address format.")]
    public string Email { get; set; } = string.Empty;

    [BindProperty]
    [StringLength(255, MinimumLength = 8, ErrorMessage = "Password must be a minimum of 8 characters, max of 255")]
    public string Password { get; set; } = string.Empty;

    public IActionResult OnPost()
    {
        if (!ModelState.IsValid)
            return Page();

        var result = UserService.CreateUser(Username, Email, Password, Config, IpAddress, UserAgent);

        if (!result.Success)
        {
            ModelState.AddModelError(string.Empty, result.Error ?? "Failed to create user.");
            return Page();
        }

        TempData["Success"] = $"User '{Username}' created successfully.";
        return RedirectToPage("/Admin/Users/Index");
    }
}
