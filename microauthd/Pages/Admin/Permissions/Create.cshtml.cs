using microauthd.Common;
using microauthd.Services;
using microauthd.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace microauthd.Pages.Admin.Permissions;

[Authorize(Roles = Constants.MadAdmin)]
public class CreateModel : BasePageModel
{
    [BindProperty]
    public EditPermissionModel PermissionForm { get; set; } = new();

    public void OnGet()
    {
        // Nothing to do
    }

    public IActionResult OnPost()
    {
        if (!ModelState.IsValid)
            return Page();

        var result = PermissionService.CreatePermission(
            PermissionForm.Name,
            Config,
            UserId,
            IpAddress,
            UserAgent
        );

        if (!result.Success)
        {
            ModelState.AddModelError(string.Empty, result.Error ?? "Creation failed.");
            return Page();
        }

        TempData["Success"] = $"Permission '{PermissionForm.Name}' created successfully.";
        return RedirectToPage("/Admin/Permissions/Index");
    }
}
