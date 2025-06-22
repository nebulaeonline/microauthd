using madTypes.Api.Common;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;
using microauthd.Data;
using microauthd.Services;

namespace microauthd.Pages.Admin.Permissions;

[Authorize]
public class IndexModel : BasePageModel
{
    public List<PermissionObject> Permissions { get; private set; } = [];
    public int TotalCount { get; private set; }
    public int CurrentPage { get; private set; }
    public int PageSize { get; private set; } = 10;

    public void OnGet(int pg = 1, int pageSize = 10)
    {
        PageSize = pageSize;
        CurrentPage = pg < 1 ? 1 : pg;
        var offset = (CurrentPage - 1) * PageSize;

        Permissions = PermissionStore.ListPermissions(offset, PageSize);
        TotalCount = PermissionStore.GetPermissionCount(); // already implemented
    }
}
