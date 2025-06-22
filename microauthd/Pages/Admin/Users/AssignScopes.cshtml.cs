using madTypes.Api.Common;
using microauthd.Common;
using microauthd.Data;
using microauthd.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace microauthd.Pages.Admin.Users;

[Authorize(Roles = Constants.MadAdmin)]
public class AssignScopesModel : BasePageModel
{
    [BindProperty(SupportsGet = true, Name = "id")]
    public string TargetUserId { get; set; } = string.Empty;

    [BindProperty]
    public List<string> SelectedScopeIds { get; set; } = new();

    public string Username { get; set; } = string.Empty;

    public List<ScopeDto> AllScopes { get; set; } = [];
    public List<ScopeDto> AssignedScopes { get; set; } = [];
    public List<ScopeDto> AvailableScopes =>
        AllScopes.Where(s => !AssignedScopes.Any(a => a.Id == s.Id)).ToList();

    public IActionResult OnGet()
    {
        if (string.IsNullOrWhiteSpace(TargetUserId))
            return RedirectToPage("/Admin/Users/Index");

        var user = UserStore.GetUserById(TargetUserId);
        if (user is null)
            return NotFound();

        Username = user.Username;
        AllScopes = ScopeStore.GetAllScopeDtos() ?? [];
        AssignedScopes = ScopeStore.GetAssignedScopesForUser(TargetUserId) ?? [];

        return Page();
    }

    public IActionResult OnPost()
    {
        if (string.IsNullOrWhiteSpace(TargetUserId))
            return RedirectToPage("/Admin/Users/Index");

        var dto = new ScopeAssignmentDto
        {
            TargetId = TargetUserId,
            Scopes = SelectedScopeIds.Select(id => new ScopeDto { Id = id, Name = "" }).ToList()
        };

        var result = UserService.ReplaceUserScopes(dto, Config, UserId, IpAddress, UserAgent);

        if (!result.Success)
        {
            ModelState.AddModelError(string.Empty, result.Error ?? "Failed to update scopes.");
            return Page();
        }

        TempData["Success"] = "Scopes updated successfully.";
        return RedirectToPage("/Admin/Users/Index");
    }
}
