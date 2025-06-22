using madTypes.Api.Responses;
using microauthd.Common;
using microauthd.Data;
using microauthd.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace microauthd.Pages.Admin.Audit;

[Authorize(Roles = Constants.MadAdmin)]
public class IndexModel : BasePageModel
{
    public List<AuditLogResponse> Logs { get; set; } = [];
    public int TotalCount { get; set; }
    public int CurrentPage { get; set; }

    [BindProperty(SupportsGet = true)]
    public int PageSize { get; set; } = 25;

    public void OnGet(int page = 1)
    {
        CurrentPage = page < 1 ? 1 : page;
        var offset = (CurrentPage - 1) * PageSize;

        Logs = AuditStore.ListAuditLogs(offset, PageSize) ?? [];
        TotalCount = AuditService.GetAuditLogCount();
    }
}

