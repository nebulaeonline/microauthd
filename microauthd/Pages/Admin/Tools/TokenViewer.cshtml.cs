using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using madJwtInspector;

namespace microauthd.Pages.Tools;

public class TokenViewerModel : PageModel
{
    [BindProperty]
    public string? JwtInput { get; set; }

    public JwtIntrospectionResult? Result { get; set; }

    public void OnPost()
    {
        if (!string.IsNullOrWhiteSpace(JwtInput))
        {
            Result = JwtInspector.Decode(JwtInput);
        }
    }
}
