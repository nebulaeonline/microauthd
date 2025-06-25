using madTypes.Api.Responses;
using microauthd.Common;
using microauthd.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace microauthd.Pages.Admin.RefreshTokens;

[Authorize(Roles = Constants.MadAdmin)]
public class IndexModel : BasePageModel
{
    public List<RefreshTokenResponse> Tokens { get; set; } = [];
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
        if (!OlderThan.HasValue)
        {
            TempData["Error"] = "You must provide a valid cutoff date/time.";
            return RedirectToPage();
        }

        if (!PurgeExpired && !PurgeRevoked)
        {
            TempData["Error"] = "Select at least one purge condition (expired or revoked).";
            return RedirectToPage();
        }

        var (success, purged) = UserStore.PurgeRefreshTokens(OlderThan.Value, PurgeExpired, PurgeRevoked);

        if (success)
            TempData["Success"] = $"Purged {purged} refresh token(s).";
        else
            TempData["Error"] = "Failed to purge refresh tokens.";

        return RedirectToPage();
    }

    public void OnGet(int pg = 1)
    {
        CurrentPage = pg < 1 ? 1 : pg;
        var offset = (CurrentPage - 1) * PageSize;

        Tokens = UserStore.ListRefreshTokensWithUsername(offset, PageSize) ?? [];
        TotalCount = UserStore.GetRefreshTokenCount();
    }

    public IActionResult OnPostRevoke(string id)
    {
        UserStore.RevokeRefreshToken(id);
        TempData["Success"] = "Refresh token revoked.";
        return RedirectToPage();
    }

    public IActionResult OnPostRevokeAllForUser(string userId)
    {
        UserStore.RevokeUserRefreshTokens(userId);
        TempData["Success"] = $"Revoked all refresh tokens for user {userId}.";
        return RedirectToPage();
    }
}

