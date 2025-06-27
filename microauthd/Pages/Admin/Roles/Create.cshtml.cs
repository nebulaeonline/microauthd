using microauthd.Common;
using microauthd.Services;
using microauthd.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace microauthd.Pages.Admin.Roles;

[Authorize(Roles = Constants.MadAdmin)]
public class CreateModel : BasePageModel
{
    [BindProperty]
    public EditRoleModel RoleForm { get; set; } = new();

    public void OnGet() { }

    public IActionResult OnPost()
    {
        if (!ModelState.IsValid)
            return Page();

        var role = RoleForm.ToRoleObject();
        var result = RoleService.CreateRole(role.Name, role.Description, Config);

        if (!result.Success)
        {
            ModelState.AddModelError(string.Empty, result.Error ?? "Failed to create role.");
            return Page();
        }

        TempData["Success"] = $"Role '{role.Name}' created successfully.";
        return RedirectToPage("/Admin/Roles/Index");
    }
}
