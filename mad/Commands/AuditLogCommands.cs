using System.CommandLine;
using System.Text.Json;
using mad.Common;
using mad.Http;
using madTypes.Api.Responses;

namespace mad.Commands;

internal static class AuditLogCommands
{
    public static Command Build()
    {
        var cmd = new Command("auditlog", "View audit log entries");

        cmd.AddCommand(ListCommand());
        cmd.AddCommand(GetByIdCommand());
        cmd.AddCommand(PurgeCommand());

        return cmd;
    }

    private static Command ListCommand()
    {
        var cmd = new Command("list", "List recent audit log entries");

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var userId = new Option<string?>("--user-id", description: "Filter by user ID");
        var action = new Option<string?>("--action", description: "Filter by action keyword");
        var limit = new Option<int?>("--limit", description: "Max number of entries to return");
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(userId);
        cmd.AddOption(action);
        cmd.AddOption(limit);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string url, string? token, string? uid, string? act, int? lim, bool json) =>
        {
            try
            {
                token ??= AuthUtils.TryLoadToken();
                if (string.IsNullOrWhiteSpace(token))
                {
                    Console.Error.WriteLine("No token. Use --admin-token or run `mad session login`.");
                    return;
                }

                var client = new MadApiClient(url, token);
                var entries = await client.ListAuditLogs(uid, act, lim);

                if (entries is null || entries.Count == 0)
                {
                    Console.WriteLine(json ? "[]" : "(no audit log entries)");
                    return;
                }

                if (json)
                {
                    if (entries.Count == 0)
                    {
                        Console.WriteLine(JsonSerializer.Serialize(
                            new MessageResponse(true, "No audit log entries found"),
                            MadJsonContext.Default.MessageResponse));
                    }
                    else
                    {
                        Console.WriteLine(JsonSerializer.Serialize(entries, MadJsonContext.Default.ListAuditLogResponse));
                    }
                    return;
                }

                Console.WriteLine($"{"Id",-36}  {"User",-36}  {"Action",-20}  {"Target",-20}  {"Secondary",-20} Time");
                Console.WriteLine(new string('-', 140));
                foreach (var e in entries)
                {
                    Console.WriteLine($"{e.Id,-36}  {e.ActorId,-36}  {e.Action,-20}  {e.Target,-20}  {e.Secondary,-20} {e.Timestamp:u}");
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Failed to list audit log entries.");
                Console.Error.WriteLine(ex.Message);
            }
        }, adminUrl, adminToken, userId, action, limit, jsonOut);

        return cmd;
    }

    private static Command GetByIdCommand()
    {
        var cmd = new Command("get", "Get audit log entry by ID");

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var id = new Option<string>("--id") { IsRequired = true };

        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(id);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string url, string? token, string entryId, bool json) =>
        {
            try
            {
                token ??= AuthUtils.TryLoadToken();
                if (string.IsNullOrWhiteSpace(token))
                {
                    Console.Error.WriteLine("No token. Use --admin-token or run `mad session login`.");
                    return;
                }

                var client = new MadApiClient(url, token);
                var entry = await client.GetAuditLogById(entryId);

                if (entry == null)
                {
                    if (json)
                    {
                        Console.WriteLine(JsonSerializer.Serialize(
                            new ErrorResponse(false, $"Audit entry {entryId} not found."),
                            MadJsonContext.Default.ErrorResponse));
                    }
                    else
                    {
                        Console.Error.WriteLine($"Audit entry {entryId} not found.");
                    }
                    return;
                }

                if (json)
                {
                    Console.WriteLine(JsonSerializer.Serialize(entry, MadJsonContext.Default.AuditLogResponse));
                }
                else
                {
                    Console.WriteLine("Audit Log Entry");
                    Console.WriteLine(new string('-', 80));
                    Console.WriteLine($"Id:         {entry.Id}");
                    Console.WriteLine($"UserId:     {entry.ActorId}");
                    Console.WriteLine($"Action:     {entry.Action}");
                    Console.WriteLine($"Target:     {entry.Target}");
                    Console.WriteLine($"Secondary:  {entry.Secondary ?? "(none)"}");
                    Console.WriteLine($"Timestamp:  {entry.Timestamp:u}");
                    Console.WriteLine($"IP Address: {entry.IpAddress ?? "(none)"}");
                    Console.WriteLine($"User Agent: {entry.UserAgent ?? "(none)"}");
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Failed to retrieve audit log entry {entryId}.");
                Console.Error.WriteLine(ex.Message);
            }
        }, adminUrl, adminToken, id, jsonOut);

        return cmd;
    }

    private static Command PurgeCommand()
    {
        var cmd = new Command("purge", "Delete audit logs older than N days");

        var days = new Option<int>("--days", "Purge entries older than this many days") { IsRequired = true };
        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;

        cmd.AddOption(days);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);

        var jsonOut = SharedOptions.OutputJson;
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (int daysOld, string url, string? token, bool json) =>
        {
            try
            {
                token ??= AuthUtils.TryLoadToken();
                if (string.IsNullOrWhiteSpace(token))
                {
                    Console.Error.WriteLine("No token. Use --admin-token or run `mad session login`.");
                    return;
                }

                if (daysOld <= 0)
                {
                    Console.Error.WriteLine("--days must be greater than 0.");
                    return;
                }

                var client = new MadApiClient(url, token);
                var ok = await client.PurgeAuditLogs(daysOld);

                if (json)
                {
                    if (ok)
                        Console.WriteLine(JsonSerializer.Serialize(
                            new MessageResponse(true, $"Purged audit logs older than {daysOld} days."),
                            MadJsonContext.Default.MessageResponse));
                    else
                        Console.WriteLine(JsonSerializer.Serialize(
                            new ErrorResponse(false, "Purge failed."),
                            MadJsonContext.Default.ErrorResponse));
                }
                else
                {
                    Console.WriteLine(ok
                        ? $"Purged audit logs older than {daysOld} days."
                        : "Purge failed.");
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Failed to purge audit logs.");
                Console.Error.WriteLine(ex.Message);
            }
        }, days, adminUrl, adminToken, jsonOut);

        return cmd;
    }

}
