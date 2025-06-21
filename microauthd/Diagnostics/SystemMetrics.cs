using microauthd.Data;
using microauthd.Services;

namespace microauthd.Diagnostics;

public static class SystemMetrics
{
    public static int ActiveUserCount => UserService.GetUserCount();
    public static int InactiveUserCount => UserService.GetInactiveUserCount();
    public static int RoleCount => RoleService.GetRoleCount();
    public static int ClientCount => ClientService.GetClientCount();
    public static int ScopeCount => ScopeService.GetScopeCount();
    public static int AuditLogCount => AuditService.GetAuditLogCount();
    public static int ActiveSessionCount => UserService.GetUserSessionCount();
}
