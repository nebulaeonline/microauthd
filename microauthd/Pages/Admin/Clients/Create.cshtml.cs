using madTypes.Api.Common;
using microauthd.Common;
using microauthd.Config;
using microauthd.Services;
using microauthd.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Components.Forms;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace microauthd.Pages.Admin.Clients;

[Authorize(Roles = Constants.MadAdmin)]
public class CreateModel : BasePageModel
{
    [BindProperty]
    public EditClientModel ClientForm { get; set; } = new();

    public string? PlainSecret { get; private set; }

    public IActionResult OnGet() => Page();

    public IActionResult OnPost()
    {
        if (!ModelState.IsValid)
            return Page();

        // Generate and stash a one-time secret
        var generatedSecret = AuthService.GeneratePassword(32);
        ClientForm.ClientSecret = generatedSecret;

        ModelState.Clear();

        var result = ClientService.TryCreateClient(ClientForm.ToClientRequest(), Config, UserId, IpAddress, UserAgent);

        if (!result.Success || result.Value == null)
        {
            ModelState.AddModelError(string.Empty, result.Error ?? "Failed to create client.");
            return Page();
        }

        ClientForm = EditClientModel.FromClientObject(result.Value);

        TempData["GeneratedSecret"] = generatedSecret;
        TempData["Success"] = $"Client '{ClientForm.ClientId}' created.";
        return RedirectToPage("/Admin/Clients/Created", new { id = result.Value.Id });
    }
}


