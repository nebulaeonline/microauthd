using madTypes.Api.Common;
using microauthd.Common;
using microauthd.Data;
using microauthd.Services;
using microauthd.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace microauthd.Pages.Admin.Scopes;

[Authorize(Roles = Constants.MadAdmin)]
public class EditModel : BasePageModel
{
    [BindProperty]
    public EditScopeModel ScopeForm { get; set; } = new();

    public bool IsProtected { get; set; }

    public IActionResult OnGet(string? id)
    {
        if (string.IsNullOrWhiteSpace(id))
            return RedirectToPage("/Admin/Scopes/Index");

        var scope = ScopeStore.GetScopeById(id);
        if (scope is null)
            return NotFound();

        ScopeForm = EditScopeModel.FromScopeObject(scope);
        IsProtected = ScopeForm.IsProtected;

        return Page();
    }

    public IActionResult OnPost()
    {
        if (!ModelState.IsValid)
            return Page();

        var result = ScopeService.UpdateScope(
            ScopeForm.Id,
            ScopeForm.ToScopeObject(),
            Config
        );

        if (!result.Success)
        {
            ModelState.AddModelError(string.Empty, result.Error ?? "Update failed.");
            return Page();
        }

        TempData["Success"] = $"Scope '{ScopeForm.Name}' updated.";
        return RedirectToPage("/Admin/Scopes/Index");
    }

    public IActionResult OnPostDelete()
    {
        if (string.IsNullOrWhiteSpace(ScopeForm?.Id))
            return RedirectToPage("/Admin/Scopes/Index");

        var result = ScopeService.DeleteScope(ScopeForm.Id, Config);

        if (!result.Success)
        {
            ModelState.AddModelError(string.Empty, result.Error ?? "Delete failed.");
            return Page();
        }

        TempData["Success"] = "Scope permanently deleted.";
        return RedirectToPage("/Admin/Scopes/Index");
    }
}
