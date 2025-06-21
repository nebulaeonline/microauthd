using madTypes.Api.Common;
using microauthd.Common;
using microauthd.Data;
using microauthd.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace microauthd.Pages.Admin.Roles;

[Authorize(Roles = Constants.MadAdmin)]
public class IndexModel : BasePageModel
{
    public List<RoleObject> Roles { get; private set; } = [];
    public int TotalCount { get; private set; }
    public int CurrentPage { get; private set; }
    public int PageSize { get; private set; } = 10;

    public void OnGet(int pg = 1, int pageSize = 10)
    {
        CurrentPage = pg < 1 ? 1 : pg;
        PageSize = pageSize < 1 ? 10 : pageSize;

        var offset = (CurrentPage - 1) * PageSize;
        Roles = RoleStore.ListRoles(offset, PageSize);
        TotalCount = RoleService.GetRoleCount();
    }
}
