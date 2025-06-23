using microauthd.Config;
using Serilog;
using System.Net;

namespace microauthd.Logging;

public class AuditDos
{
    private readonly IHttpContextAccessor _http;
    private readonly AppConfig _config;

    public AuditDos(IHttpContextAccessor httpContextAccessor, AppConfig config)
    {
        _http = httpContextAccessor;
        _config = config;
    }

    public void Logg(string action, string? target, string? secondary = null)
    {
        var ctx = _http.HttpContext;

        var userId = ctx?.User?.FindFirst("sub")?.Value ?? "anonymous";
        var ip = ctx?.Connection?.RemoteIpAddress?.ToString() ?? "unknown";
        var ua = ctx?.Request?.Headers["User-Agent"].ToString() ?? "unknown";

        LogToStore(userId, action, target, secondary, ip, ua);
    }

    private void LogToStore(string userId, string action, string? target, string? secondary, string ip, string ua)
    {
        var id = Guid.NewGuid().ToString();
        var timestamp = DateTime.UtcNow.ToString("o");

        Db.WithConnection(conn =>
        {
            try
            {
                using var cmd = conn.CreateCommand();
                cmd.CommandText = """
                    INSERT INTO audit_logs (id, actor_id, action, target, secondary, timestamp, ip_address, user_agent)
                    VALUES ($id, $uid, $action, $target, $secondary, $ts, $ip, $ua);
                """;
                cmd.Parameters.AddWithValue("$id", id);
                cmd.Parameters.AddWithValue("$uid", (object?)userId ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$action", action);
                cmd.Parameters.AddWithValue("$target", (object?)target ?? DBNull.Value);
                cmd.Parameters.AddWithValue("secondary", (object?)secondary ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$ts", timestamp);
                cmd.Parameters.AddWithValue("$ip", (object?)ip ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$ua", (object?)ua ?? DBNull.Value);
                cmd.ExecuteNonQuery();
            }
            catch (Exception ex)
            {
                Log.Error("Failed to log audit entry for {userId} / Action: {action} / Target: {target} Secondary: {secondary} {Message}", userId, action, target, secondary, ex.Message);
            }
        });

        Log.Information("AUDIT: {Action} [{UserId}] -> {Target} -> {Secondary}", action, userId ?? "(anon)", target ?? "(none)", secondary ?? "(none)");
    }
}
