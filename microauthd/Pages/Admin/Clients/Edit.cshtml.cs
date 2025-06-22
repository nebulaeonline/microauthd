using madTypes.Api.Common;
using microauthd.Common;
using microauthd.Data;
using microauthd.Services;
using microauthd.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using nebulae.dotArgon2;

namespace microauthd.Pages.Admin.Clients;

[Authorize(Roles = Constants.MadAdmin)]
public class EditModel : BasePageModel
{
    [BindProperty]
    public EditClientModel ClientForm { get; set; } = new();

    public string? GeneratedSecret { get; set; }

    public IActionResult OnGet(string? id)
    {
        if (string.IsNullOrWhiteSpace(id))
            return RedirectToPage("/Admin/Clients/Index");

        var client = ClientStore.GetClientById(id);
        if (client == null)
            return NotFound();

        ClientForm = EditClientModel.FromClient(client);
        return Page();
    }

    public IActionResult OnPost()
    {
        if (!ModelState.IsValid)
            return Page();

        var toUpdate = ClientForm.ToClientObject();

        var result = ClientService.UpdateClient(toUpdate.Id, toUpdate, Config);
        if (!result.Success)
        {
            ModelState.AddModelError(string.Empty, result.Error ?? "Update failed.");
            return Page();
        }

        TempData["Success"] = $"Client '{toUpdate.DisplayName}' updated.";
        return RedirectToPage("/Admin/Clients/Index");
    }

    public IActionResult OnPostRegenerateSecret()
    {
        if (string.IsNullOrWhiteSpace(ClientForm?.Id))
            return RedirectToPage("/Admin/Clients/Index");

        var result = ClientService.RegenerateClientSecret(
            clientId: ClientForm.Id,
            config: Config,
            actorUserId: UserId,
            ip: IpAddress,
            ua: UserAgent
        );

        if (!result.Success)
        {
            ModelState.AddModelError(string.Empty, result.Error ?? "Secret regeneration failed.");
            return Page();
        }

        GeneratedSecret = result.Value?.Message ?? "";
        TempData["Success"] = "Client secret regenerated. Copy it now — it will not be shown again.";

        var client = ClientStore.GetClientByClientId(ClientForm.Id);
        if (client != null)
            ClientForm = EditClientModel.FromClient(client);

        return Page();
    }

    public IActionResult OnPostDelete()
    {
        if (string.IsNullOrWhiteSpace(ClientForm?.Id))
            return RedirectToPage("/Admin/Clients/Index");

        var result = ClientService.DeleteClient(ClientForm.Id, Config, UserId, IpAddress, UserAgent);

        if (!result.Success)
        {
            ModelState.AddModelError(string.Empty, result.Error ?? "Delete failed.");
            return Page();
        }

        TempData["Success"] = "Client permanently deleted.";
        return RedirectToPage("/Admin/Clients/Index");
    }
}

