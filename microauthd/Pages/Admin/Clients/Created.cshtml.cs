using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;

using microauthd.Common;

namespace microauthd.Pages.Admin.Clients;

[Authorize(Roles = Constants.MadAdmin)]
public class CreatedModel : PageModel
{
    public void OnGet() { }
}

