using madTypes.Api.Common;
using microauthd.Common;
using microauthd.Data;
using microauthd.Services;
using microauthd.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace microauthd.Pages.Admin.Roles;

[Authorize(Roles = Constants.MadAdmin)]
public class EditModel : BasePageModel
{
    [BindProperty]
    public EditRoleModel? RoleForm { get; set; }

    public IActionResult OnGet(string? id)
    {
        if (string.IsNullOrWhiteSpace(id))
        {
            RoleForm = new EditRoleModel();
            return RedirectToPage("/Admin/Roles/Index");
        }

        var role = RoleStore.GetRoleById(id);
        if (role is null)
        {
            RoleForm = new EditRoleModel();
            return NotFound();
        }

        RoleForm = EditRoleModel.FromRoleObject(role);
        return Page();
    }

    public IActionResult OnPost()
    {
        if (!ModelState.IsValid || RoleForm is null)
            return Page();

        var updated = RoleForm.ToRoleObject();
        var result = RoleService.UpdateRole(updated.Id, updated, Config);

        if (!result.Success)
        {
            ModelState.AddModelError(string.Empty, result.Error ?? "Update failed.");
            return Page();
        }

        TempData["Success"] = $"Role '{updated.Name}' updated.";
        return RedirectToPage("/Admin/Roles/Index");
    }

    public IActionResult OnPostDelete()
    {
        if (string.IsNullOrWhiteSpace(RoleForm?.Id))
            return RedirectToPage("/Admin/Roles/Index");

        var result = RoleService.DeleteRole(RoleForm.Id, Config);

        if (!result.Success)
        {
            ModelState.AddModelError(string.Empty, result.Error ?? "Delete failed.");
            return Page();
        }

        TempData["Success"] = "Role deleted.";
        return RedirectToPage("/Admin/Roles/Index");
    }
}

