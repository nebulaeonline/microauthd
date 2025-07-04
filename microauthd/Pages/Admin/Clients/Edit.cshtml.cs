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

    [BindProperty(SupportsGet = false)]
    public List<string> Features { get; set; } = new();

    [BindProperty(SupportsGet = false)]
    public Dictionary<string, string> Options { get; set; } = new();

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

        // Handle feature flag updates
        var formFlags = Request.Form["features"].ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (ClientFeatures.Flags flag in Enum.GetValues(typeof(ClientFeatures.Flags)))
        {
            var flagKey = ClientFeatures.GetFlagString(flag);
            bool shouldEnable = formFlags.Contains(flagKey);
            ClientFeaturesStore.SetClientFeatureFlag(ClientForm.Id!, flag, shouldEnable);
        }

        var formOptions = Request.Form
            .Where(kvp => kvp.Key.StartsWith("options["))
            .ToDictionary(
                kvp => kvp.Key.Substring(8, kvp.Key.Length - 9), // extract key between brackets
                kvp => kvp.Value.ToString()
            );

        foreach (var (flagString, optionValue) in formOptions)
        {
            if (ClientFeatures.Parse(flagString) is { } flag)
            {
                ClientFeaturesStore.SetFeatureOption(ClientForm.Id!, flag, optionValue ?? "");
            }
        }

        TempData["Success"] = $"Client '{toUpdate.DisplayName}' updated.";
        return RedirectToPage("/Admin/Clients/Index");
    }

    public IActionResult OnPostRegenerateSecret()
    {
        if (string.IsNullOrWhiteSpace(ClientForm?.Id))
            return RedirectToPage("/Admin/Clients/Index");

        var result = ClientService.RegenerateClientSecret(
            id: ClientForm.Id,
            config: Config
        );

        if (!result.Success)
        {
            ModelState.AddModelError(string.Empty, result.Error ?? "Secret regeneration failed.");
            return Page();
        }

        ModelState.Clear();

        var client = ClientStore.GetClientById(ClientForm.Id);
        if (client != null)
            ClientForm = EditClientModel.FromClient(client);

        GeneratedSecret = result.Value?.Message ?? "";
        return Page();
    }

    public IActionResult OnPostDelete()
    {
        if (string.IsNullOrWhiteSpace(ClientForm?.Id))
            return RedirectToPage("/Admin/Clients/Index");

        var result = ClientService.DeleteClient(ClientForm.Id, Config);

        if (!result.Success)
        {
            ModelState.AddModelError(string.Empty, result.Error ?? "Delete failed.");
            return Page();
        }

        TempData["Success"] = "Client permanently deleted.";
        return RedirectToPage("/Admin/Clients/Index");
    }
}