using microauthd.Config;
using Microsoft.AspNetCore.Http;
using Serilog;
using System;
using System.Net;
using static System.Net.WebRequestMethods;
using System.Security.Claims;

namespace microauthd.Common;

public static class AuditLogger
{
    public static void AuditLog(
    AppConfig config,
    string? userId,
    string action,
    string? target = null,
    string? ipAddress = null,
    string? userAgent = null
)
    {
        if (!config.EnableAuditLogging)
            return;

        var id = Guid.NewGuid().ToString();
        var timestamp = DateTime.UtcNow.ToString("o");

        // If this is an oidc token, we might not have a userId,
        // so we should make sure that we don't pass a non-GUID value
        // to the database, because it will fail. Audit logging 
        // should never fail.
        if (!Guid.TryParse(userId, out var guid))
        {
            userId = null;
        }

        Db.WithConnection(conn =>
        {
            try
            {
                using var cmd = conn.CreateCommand();
                cmd.CommandText = """
                    INSERT INTO audit_logs (id, user_id, action, target, timestamp, ip_address, user_agent)
                    VALUES ($id, $uid, $action, $target, $ts, $ip, $ua);
                """;
                cmd.Parameters.AddWithValue("$id", id);
                cmd.Parameters.AddWithValue("$uid", (object?)userId ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$action", action);
                cmd.Parameters.AddWithValue("$target", (object?)target ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$ts", timestamp);
                cmd.Parameters.AddWithValue("$ip", (object?)ipAddress ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$ua", (object?)userAgent ?? DBNull.Value);
                cmd.ExecuteNonQuery();
            }
            catch (Exception ex)
            {
                Log.Error("Failed to log audit entry for {userId} / Action: {action} / Target: {target} {Message}", userId, action, target, ex.Message);
            }
        });

        Log.Information("AUDIT: {Action} [{UserId}] -> {Target}", action, userId ?? "(anon)", target ?? "(none)");
    }
}
