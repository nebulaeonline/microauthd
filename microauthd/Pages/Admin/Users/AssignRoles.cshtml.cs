using madTypes.Api.Common;
using microauthd.Common;
using microauthd.Data;
using microauthd.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Text.Json;

namespace microauthd.Pages.Admin.Users;

[Authorize(Roles = Constants.MadAdmin)]
public class AssignRolesModel : BasePageModel
{
    [BindProperty(SupportsGet = true, Name = "id")]
    public string targetUserId { get; set; } = string.Empty;

    [BindProperty]
    public List<string> SelectedRoleIds { get; set; } = new();

    public string Username { get; set; } = string.Empty;

    public List<RoleDto> AllRoles { get; set; } = [];
    public List<RoleDto> AssignedRoles { get; set; } = [];
    public List<RoleDto> AvailableRoles =>
        AllRoles.Where(r => !AssignedRoles.Any(a => a.Id == r.Id)).ToList();

    public IActionResult OnGet()
    {
        if (string.IsNullOrWhiteSpace(targetUserId))
            return RedirectToPage("/Admin/Users/Index");

        var user = UserStore.GetUserById(targetUserId);
        if (user is null)
            return NotFound();

        Username = user.Username;
        AllRoles = RoleService.GetAllRoleDtos().Value ?? new();
        AssignedRoles = RoleService.GetAssignedRoleDtos(targetUserId).Value ?? new();

        return Page();
    }

    public IActionResult OnPost()
    {
        if (SelectedRoleIds != null)
        {
            foreach (var roleId in SelectedRoleIds)
            {
                Console.WriteLine($"Role ID: {roleId}");
            }
        }

        if (string.IsNullOrWhiteSpace(targetUserId) || SelectedRoleIds == null || !SelectedRoleIds.Any())
        {
            return RedirectToPage("/Admin/Users/Index");
        }

        // No JSON deserialization needed - we already have the list!
        var roleDtos = SelectedRoleIds
            .Select(id => new RoleDto { Id = id, Name = "" })
            .ToList();

        var result = RoleService.ReplaceUserRoles(
            new RoleAssignmentDto { UserId = targetUserId, Roles = roleDtos },
            Config
        );

        if (!result.Success)
        {
            ModelState.AddModelError(string.Empty, result.Error ?? "Failed to update roles.");
            return Page();
        }

        TempData["Success"] = "Roles updated successfully.";
        return RedirectToPage("/Admin/Users/Index");
    }
}
