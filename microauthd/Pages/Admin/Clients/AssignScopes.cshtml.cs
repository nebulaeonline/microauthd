using madTypes.Api.Common;
using microauthd.Common;
using microauthd.Data;
using microauthd.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace microauthd.Pages.Admin.Clients;

[Authorize(Roles = Constants.MadAdmin)]
public class AssignScopesToClientModel : BasePageModel
{
    [BindProperty(SupportsGet = true, Name = "id")]
    public string TargetClientId { get; set; } = string.Empty;

    [BindProperty]
    public List<string> SelectedScopeIds { get; set; } = new();

    public string ClientId { get; set; } = string.Empty;

    public List<ScopeDto> AllScopes { get; set; } = [];
    public List<ScopeDto> AssignedScopes { get; set; } = [];
    public List<ScopeDto> AvailableScopes =>
        AllScopes.Where(s => !AssignedScopes.Any(a => a.Id == s.Id)).ToList();

    public IActionResult OnGet()
    {
        if (string.IsNullOrWhiteSpace(TargetClientId))
            return RedirectToPage("/Admin/Clients/Index");

        var client = ClientStore.GetClientById(TargetClientId);
        if (client is null)
            return NotFound();

        ClientId = client.ClientId;
        AllScopes = ScopeStore.GetAllScopeDtos() ?? [];
        AssignedScopes = ScopeStore.GetAssignedScopesForClient(TargetClientId) ?? [];

        return Page();
    }

    public IActionResult OnPost()
    {
        if (string.IsNullOrWhiteSpace(TargetClientId))
            return RedirectToPage("/Admin/Clients/Index");

        var dto = new ScopeAssignmentDto
        {
            TargetId = TargetClientId,
            Scopes = SelectedScopeIds.Select(id => new ScopeDto { Id = id, Name = "" }).ToList()
        };

        var result = ClientService.ReplaceClientScopes(dto, Config, UserId, IpAddress, UserAgent);

        if (!result.Success)
        {
            ModelState.AddModelError(string.Empty, result.Error ?? "Failed to update scopes.");
            return Page();
        }

        TempData["Success"] = "Scopes updated successfully.";
        return RedirectToPage("/Admin/Clients/Index");
    }
}

