using microauthd.Common;
using microauthd.Diagnostics;
using Microsoft.AspNetCore.Authorization;

namespace microauthd.Pages;

[Authorize(Roles = Constants.MadAdmin)]
public class DashboardModel : BasePageModel
{
    public int UserCount { get; private set; }
    public int InactiveUserCount { get; private set; }
    public int RoleCount { get; private set; }
    public int ClientCount { get; private set; }
    public int ScopeCount { get; private set; }
    public int AuditLogCount { get; private set; }
    public int ActiveSessionCount { get; private set; }
    public int TotalSessionCount { get; private set; }

    public void OnGet()
    {
        UserCount = SystemMetrics.ActiveUserCount;
        InactiveUserCount = SystemMetrics.InactiveUserCount;
        RoleCount = SystemMetrics.RoleCount;
        ClientCount = SystemMetrics.ClientCount;
        ScopeCount = SystemMetrics.ScopeCount;
        AuditLogCount = SystemMetrics.AuditLogCount;
        ActiveSessionCount = SystemMetrics.ActiveSessionCount;
        TotalSessionCount = SystemMetrics.TotalSessionCount;
    }
}