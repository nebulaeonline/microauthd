using madTypes.Api.Responses;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using microauthd.Data;
using microauthd.Common;

namespace microauthd.Pages.Admin.Sessions;

[Authorize(Roles = Constants.MadAdmin)]
public class IndexModel : BasePageModel
{
    public List<SessionResponse> Sessions { get; set; } = [];
    public int TotalCount { get; set; }
    public int CurrentPage { get; set; }

    [BindProperty(SupportsGet = true)]
    public int PageSize { get; set; } = 25;
    [BindProperty]
    public DateTime? OlderThan { get; set; }

    [BindProperty]
    public bool PurgeExpired { get; set; }

    [BindProperty]
    public bool PurgeRevoked { get; set; }

    public IActionResult OnPostPurge()
    {
        if (OlderThan is null || (!PurgeExpired && !PurgeRevoked))
        {
            TempData["Error"] = "Please select a date and at least one purge type.";
            return RedirectToPage(); // or return Page() if you want validation to persist
        }

        var count = UserStore.PurgeSessions(OlderThan.Value, PurgeExpired, PurgeRevoked);
        TempData["Success"] = $"Purged {count} session(s).";

        return RedirectToPage();
    }

    public IActionResult OnPostRevoke(string id)
    {
        if (string.IsNullOrWhiteSpace(id))
        {
            TempData["Error"] = "Missing session ID.";
            return RedirectToPage();
        }

        var result = UserStore.RevokeSessionById(id);

        if (result.revoked)
        {
            TempData["Success"] = $"Session {id} revoked.";
        }
        else
        {
            TempData["Error"] = $"Failed to revoke session {id}.";
        }

        return RedirectToPage(new { pg = CurrentPage, pageSize = PageSize });
    }

    public IActionResult OnPostRevokeAllForUser(string userId)
    {
        if (string.IsNullOrWhiteSpace(userId))
        {
            TempData["Error"] = "Missing user ID.";
            return RedirectToPage();
        }

        var revoked = UserStore.RevokeUserSessions(userId);

        if (revoked)
            TempData["Success"] = $"Revoked all session(s) for user {userId}.";
        else
            TempData["Info"] = $"No sessions to revoke for user {userId}.";

        return RedirectToPage(new { pg = CurrentPage, pageSize = PageSize });
    }

    public void OnGet(int pg = 1)
    {
        CurrentPage = pg < 1 ? 1 : pg;
        var offset = (CurrentPage - 1) * PageSize;

        Sessions = UserStore.ListSessions(offset, PageSize);
        TotalCount = UserStore.GetUserSessionCount();
    }
}
