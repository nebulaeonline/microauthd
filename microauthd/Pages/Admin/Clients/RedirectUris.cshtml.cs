using madTypes.Api.Common;
using microauthd.Data;
using microauthd.Common;
using microauthd.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace microauthd.Pages.Admin.Clients;

[Authorize(Roles = Constants.MadAdmin)]
public class RedirectUrisModel : BasePageModel
{
    public string ClientId { get; set; } = string.Empty;
    public List<ClientRedirectUriObject> RedirectUris { get; set; } = new();

    [BindProperty]
    public string NewUri { get; set; } = string.Empty;

    [BindProperty(SupportsGet = true)]
    public string Id { get; set; } = string.Empty;

    public string? Error { get; set; }
    public string? Success { get; set; }

    public IActionResult OnGet()
    {
        if (string.IsNullOrWhiteSpace(Id))
            return RedirectToPage("/Admin/Clients/Index");

        var client = ClientStore.GetClientById(Id);
        if (client == null)
            return NotFound();

        ClientId = client.ClientId;
        RedirectUris = ClientService.GetRedirectUrisForClient(Id).Value ?? new();
        return Page();
    }

    public IActionResult OnPost()
    {
        if (string.IsNullOrWhiteSpace(Id) || string.IsNullOrWhiteSpace(NewUri))
        {
            Error = "Redirect URI cannot be empty.";
            return OnGet(); // reload list
        }

        var result = ClientService.AddRedirectUri(Id, NewUri);
        if (!result.Success)
        {
            Error = result.Error;
        }
        else
        {
            Success = "Redirect URI added.";
        }

        return OnGet(); // refresh
    }

    public IActionResult OnPostDelete(string uriId)
    {
        if (string.IsNullOrWhiteSpace(uriId))
        {
            Error = "Invalid redirect URI.";
            return RedirectToPage(new { id = Id });
        }

        var result = ClientService.DeleteRedirectUri(uriId);
        if (!result.Success)
        {
            Error = result.Error;
        }
        else
        {
            Success = "Redirect URI deleted.";
        }

        return RedirectToPage(new { id = Id });
    }
}
