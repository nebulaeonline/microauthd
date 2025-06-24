using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace madRazorExample.Pages;

[Authorize]
public class SecurePageModel : PageModel
{
    public void OnGet() { }
}

