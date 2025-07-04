using madTypes.Api.Requests;
using microauthd.Config;
using microauthd.Services;
using Microsoft.Extensions.Hosting;
using System.Threading;
using System.Threading.Tasks;
using Serilog;
using microauthd.Data;

/// <summary>
/// A background service that performs scheduled maintenance tasks, such as purging audit logs,  expired sessions, and
/// revoked refresh tokens, at regular intervals.
/// </summary>
/// <remarks>This service runs continuously in the background and executes maintenance tasks based on 
/// configuration settings provided in the <see cref="AppConfig"/> instance. The tasks include: <list type="bullet">
/// <item><description>Purging audit logs older than the configured retention period.</description></item>
/// <item><description>Purging expired and revoked user sessions.</description></item> <item><description>Purging
/// expired and revoked refresh tokens.</description></item> </list> The service runs these tasks every hour and logs
/// the results of each operation. If an error occurs  during execution, it is logged without interrupting the
/// service.</remarks>
public class ScheduledTaskService : BackgroundService
{
    private readonly AppConfig _config;

    public ScheduledTaskService(AppConfig config)
    {
        _config = config;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        Log.Information("ScheduledTaskService started.");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                // Purge audit logs
                if (_config.AuditLogRetentionDays > 0)
                {
                    AuditService.PurgeLogsOlderThan(TimeSpan.FromDays(_config.AuditLogRetentionDays));
                    Log.Information("Purged audit logs older than {Days} days", _config.AuditLogRetentionDays);
                }

                // Purge expired & revoked sessions
                if (_config.TokenPurgeDays > 0)
                {
                    UserService.PurgeSessions(DateTime.UtcNow.Subtract(TimeSpan.FromDays(_config.TokenPurgeDays)), true, true, _config);
                    Log.Information("Purged sessions older than {Days} days", _config.TokenPurgeDays);
                }

                // Purge expired & revoked refresh tokens
                if (_config.RefreshTokenPurgeDays > 0)
                {
                    UserService.PurgeRefreshTokens(new PurgeTokensRequest(_config.RefreshTokenPurgeDays * 60 * 60 * 24, true, true), _config);
                    Log.Information("Purged refresh tokens older than {Days} days", _config.RefreshTokenPurgeDays);
                }

                // Purge old nonces for OIDC PKCE logins after 2 days
                AuthStore.PurgeNonces(DateTime.UtcNow.AddDays(-2));

                // Purge expired auth sessions
                AuthSessionStore.PurgeExpired();

                // Run every hour
                await Task.Delay(TimeSpan.FromHours(1), stoppingToken);
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Error in ScheduledTaskService loop");
            }
        }

        Log.Information("ScheduledTaskService shutting down.");
    }
}
