using madTypes.Api.Common;
using microauthd.Common;
using microauthd.Config;
using microauthd.Services;
using microauthd.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace microauthd.Pages.Admin.Scopes;

[Authorize(Roles = Constants.MadAdmin)]
public class CreateModel : BasePageModel
{
    [BindProperty]
    public EditScopeModel ScopeForm { get; set; } = new();

    public IActionResult OnGet() => Page();

    public IActionResult OnPost()
    {
        if (!ModelState.IsValid)
            return Page();

        var result = ScopeService.CreateScope(ScopeForm.ToScopeObject(), Config);

        if (!result.Success)
        {
            ModelState.AddModelError(string.Empty, result.Error ?? "Failed to create scope.");
            return Page();
        }

        TempData["Success"] = $"Scope '{ScopeForm.Name}' created.";
        return RedirectToPage("/Admin/Scopes/Index");
    }
}

