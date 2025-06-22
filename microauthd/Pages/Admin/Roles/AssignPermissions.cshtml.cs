using madTypes.Api.Common;
using microauthd.Common;
using microauthd.Data;
using microauthd.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace microauthd.Pages.Admin.Roles;

[Authorize(Roles = Constants.MadAdmin)]
public class AssignPermissionsModel : BasePageModel
{
    [BindProperty(SupportsGet = true, Name = "id")]
    public string targetRoleId { get; set; } = string.Empty;

    [BindProperty]
    public List<string> SelectedPermissionIds { get; set; } = new();

    public string RoleName { get; set; } = string.Empty;

    public List<PermissionDto> AllPermissions { get; set; } = [];
    public List<PermissionDto> AssignedPermissions { get; set; } = [];

    public List<PermissionDto> AvailablePermissions =>
        AllPermissions.Where(p => !AssignedPermissions.Any(a => a.Id == p.Id)).ToList();

    public IActionResult OnGet()
    {
        if (string.IsNullOrWhiteSpace(targetRoleId))
            return RedirectToPage("/Admin/Roles/Index");

        var role = RoleStore.GetRoleById(targetRoleId);
        if (role is null)
            return NotFound();

        RoleName = role.Name;
        AllPermissions = PermissionService.GetAllPermissionDtos().Value ?? new();
        AssignedPermissions = PermissionService.GetAssignedPermissionDtos(targetRoleId).Value ?? new();

        return Page();
    }

    public IActionResult OnPost()
    {
        if (string.IsNullOrWhiteSpace(targetRoleId) || SelectedPermissionIds == null || !SelectedPermissionIds.Any())
        {
            return RedirectToPage("/Admin/Roles/Index");
        }

        var permissionDtos = SelectedPermissionIds
            .Select(id => new PermissionDto { Id = id, Name = "" })
            .ToList();

        var result = PermissionService.ReplaceRolePermissions(
            new PermissionAssignmentDto { RoleId = targetRoleId, Permissions = permissionDtos },
            Config,
            actorUserId: UserId,
            IpAddress,
            UserAgent
        );

        if (!result.Success)
        {
            ModelState.AddModelError(string.Empty, result.Error ?? "Failed to update permissions.");
            return Page();
        }

        TempData["Success"] = "Permissions updated successfully.";
        return RedirectToPage("/Admin/Roles/Index");
    }
}

