using madTypes.Api.Common;
using microauthd.Common;
using microauthd.Data;
using microauthd.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Net;

namespace microauthd.Pages.Admin.Users;

[Authorize(Roles = Constants.MadAdmin)]
public class IndexModel : BasePageModel
{
    public List<UserObject> Users { get; private set; } = [];
    public int TotalCount { get; private set; }
    public int CurrentPage { get; private set; }
    public int PageSize { get; private set; } = 10;
    public bool InactiveView { get; private set; }

    public void OnGet(int pg = 1, int pageSize = 10, bool inactive = false)
    {
        InactiveView = inactive;
        CurrentPage = pg < 1 ? 1 : pg;
        PageSize = pageSize < 1 ? 10 : pageSize;

        var offset = (CurrentPage - 1) * PageSize;

        Users = inactive
            ? UserStore.ListInactiveUsers(offset, PageSize)
            : UserStore.ListUsers(offset, PageSize);

        TotalCount = inactive
            ? UserStore.GetInactiveUserCount()
            : UserService.GetUserCount();
    }

    public async Task<IActionResult> OnPostActivateAsync(string id)
    {
        if (string.IsNullOrWhiteSpace(id))
            return RedirectToPage();

        UserService.ReactivateSoftDeletedUser(id, Config);

        return RedirectToPage(new { pg = CurrentPage, inactive = true });
    }

    public async Task<IActionResult> OnPostDeactivateAsync(string id)
    {
        if (string.IsNullOrWhiteSpace(id))
            return RedirectToPage();

        UserService.DeactivateUser(id, Config);
        return RedirectToPage(new { pg = CurrentPage, inactive = true });
    }
}