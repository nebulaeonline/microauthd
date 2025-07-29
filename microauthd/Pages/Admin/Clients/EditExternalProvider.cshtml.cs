using madTypes.Api.Common;
using microauthd.Data;
using microauthd.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using microauthd.Common;

namespace microauthd.Pages.Admin.Clients;

[Authorize(Roles = Constants.MadAdmin)]
public class EditExternalProviderModel : BasePageModel
{
    [BindProperty(SupportsGet = true)]
    public string? Id { get; set; }

    [BindProperty(SupportsGet = true)]
    public string? ClientId { get; set; }

    [BindProperty]
    public EditExternalIdpModel Form { get; set; } = new();

    public IActionResult OnGet()
    {
        if (string.IsNullOrWhiteSpace(ClientId))
            return RedirectToPage("/Admin/Clients/Index");

        if (!string.IsNullOrWhiteSpace(Id))
        {
            var dto = ClientStore.GetExternalIdpByKey(ClientId, ClientStore.GetExternalIdpsForClient(ClientId).FirstOrDefault(x => x.Id == Id)?.ProviderKey ?? "");
            if (dto is null)
                return NotFound();
            Form = EditExternalIdpModel.FromDto(dto);
        }
        else
        {
            Form.ClientId = ClientId;
        }

        return Page();
    }

    public IActionResult OnPost()
    {
        ModelState.Remove("Form.Id");

        if (!ModelState.IsValid)
        {
            foreach (var entry in ModelState)
            {
                foreach (var error in entry.Value.Errors)
                {
                    Console.WriteLine($"ModelState Error - {entry.Key}: {error.ErrorMessage}");
                }
            }
            return Page();
        }

        var dto = Form.ToDto();

        var result = string.IsNullOrWhiteSpace(Form.Id)
            ? ClientStore.InsertExternalIdpProvider(dto)
            : ClientStore.UpdateExternalIdpProvider(dto);

        if (result is null)
        {
            ModelState.AddModelError(string.Empty, "Failed to save external provider.");
            return Page();
        }

        return RedirectToPage("/Admin/Clients/ExternalProviders", new { clientId = Form.ClientId });
    }
}

