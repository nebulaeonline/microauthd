using madTypes.Api.Common;
using microauthd.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using microauthd.Common;

namespace microauthd.Pages.Admin.Clients;

[Authorize(Roles = Constants.MadAdmin)]
public class ExternalProvidersModel : BasePageModel
{
    [BindProperty(SupportsGet = true)]
    public string? ClientId { get; set; }

    public List<ExternalIdpProviderDto> Providers { get; set; } = new();

    public IActionResult OnGet()
    {
        if (string.IsNullOrWhiteSpace(ClientId))
            return RedirectToPage("/Admin/Clients/Index");

        Providers = ClientStore.GetExternalIdpsForClient(ClientId);
        return Page();
    }

    public IActionResult OnPostDelete(string id, string clientId)
    {
        if (!ClientStore.DeleteExternalIdpProvider(id, clientId))
        {
            TempData["Error"] = "Failed to delete provider.";
        }

        return RedirectToPage("/Admin/Clients/ExternalProviders", new { clientId });
    }
}

