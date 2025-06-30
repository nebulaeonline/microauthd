using madTypes.Api.Requests;
using microauthd.Config;
using microauthd.Services;
using Microsoft.Extensions.Hosting;
using System.Threading;
using System.Threading.Tasks;
using Serilog;

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
