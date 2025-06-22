using madTypes.Api.Common;
using microauthd.Common;
using microauthd.Data;
using microauthd.Services;
using microauthd.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace microauthd.Pages.Admin.Permissions;

[Authorize(Roles = Constants.MadAdmin)]
public class EditModel : BasePageModel
{
    [BindProperty]
    public EditPermissionModel PermissionForm { get; set; } = new();

    public IActionResult OnGet(string? id)
    {
        if (string.IsNullOrWhiteSpace(id))
            return RedirectToPage("/Admin/Permissions/Index");

        var permission = PermissionStore.GetPermissionById(id);
        if (permission is null)
            return NotFound();

        PermissionForm = EditPermissionModel.FromPermissionObject(permission);
        return Page();
    }

    public IActionResult OnPost()
    {
        if (!ModelState.IsValid)
            return Page();

        var toUpdate = PermissionForm.ToPermissionObject();

        var result = PermissionService.UpdatePermission(toUpdate.Id, toUpdate, Config);
        if (!result.Success)
        {
            ModelState.AddModelError(string.Empty, result.Error ?? "Update failed.");
            return Page();
        }

        TempData["Success"] = $"Permission '{toUpdate.Name}' updated.";
        return RedirectToPage("/Admin/Permissions/Index");
    }

    public IActionResult OnPostDelete()
    {
        if (string.IsNullOrWhiteSpace(PermissionForm?.Id))
            return RedirectToPage("/Admin/Permissions/Index");

        var result = PermissionService.DeletePermission(
            PermissionForm.Id,
            Config,
            UserId,
            IpAddress,
            UserAgent
        );

        if (!result.Success)
        {
            ModelState.AddModelError(string.Empty, result.Error ?? "Delete failed.");
            return Page();
        }

        TempData["Success"] = "Permission permanently deleted.";
        return RedirectToPage("/Admin/Permissions/Index");
    }
}

