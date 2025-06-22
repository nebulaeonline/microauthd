using microauthd.Data;
using microauthd.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;
using microauthd.Common;
using madTypes.Api.Common;

namespace microauthd.Pages.Admin.Scopes;

[Authorize(Roles = Constants.MadAdmin)]
public class IndexModel : BasePageModel
{
    public List<ScopeObject> Scopes { get; set; } = [];
    public int TotalCount { get; set; }
    public int CurrentPage { get; set; }
    public int PageSize { get; set; } = 10;

    public void OnGet(int pg = 1, int pageSize = 10)
    {
        PageSize = pageSize;
        CurrentPage = pg < 1 ? 1 : pg;
        var offset = (CurrentPage - 1) * PageSize;

        Scopes = ScopeStore.ListScopes(offset, PageSize);
        TotalCount = ScopeService.GetScopeCount();
    }
}
