using System.CommandLine;
using System.Text.Json;
using mad.Common;
using mad.Http;
using madTypes.Api.Responses;

namespace mad.Commands;

internal static class SessionCtlCommands
{
    public static Command Build()
    {
        var cmd = new Command("sessionctl", "Manage active user sessions");

        cmd.AddCommand(ListAllCommand());
        cmd.AddCommand(IntrospectTokenCommand());
        cmd.AddCommand(GetByIdCommand());
        cmd.AddCommand(ListByUserCommand());

        cmd.AddCommand(RevokeCommand());
        cmd.AddCommand(PurgeCommand());
        
        return cmd;
    }

    private static Command ListAllCommand()
    {
        var cmd = new Command("list", "List all active sessions");

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string url, string? token, bool json) =>
        {
            try
            {
                token ??= AuthUtils.TryLoadToken();
                if (string.IsNullOrWhiteSpace(token))
                {
                    Console.Error.WriteLine("No token.");
                    return;
                }

                var client = new MadApiClient(url, token);
                var sessions = await client.ListSessions();

                if (sessions is null || sessions.Count == 0)
                {
                    Console.WriteLine(json ? "[]" : "(no sessions)");
                    return;
                }

                if (json)
                {
                    Console.WriteLine(JsonSerializer.Serialize(sessions, MadJsonContext.Default.ListSessionResponse));
                    return;
                }

                Console.WriteLine($"{"Id",-36}  {"UserId",-36}  {"Use",-5}  {"Revoked",-7}  Expires At");
                Console.WriteLine(new string('-', 120));
                foreach (var s in sessions)
                {
                    Console.WriteLine($"{s.Id,-36}  {s.UserId,-36}  {s.TokenUse,-5}  {s.IsRevoked,-7}  {s.ExpiresAt:u}");
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Failed to list sessions.");
                Console.Error.WriteLine(ex.Message);
            }
        }, adminUrl, adminToken, jsonOut);

        return cmd;
    }

    private static Command GetByIdCommand()
    {
        var cmd = new Command("get", "Get a session by ID");

        var sessionId = new Option<string>("--id") { IsRequired = true };
        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(sessionId);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string url, string? token, string id, bool json) =>
        {
            try
            {
                token ??= AuthUtils.TryLoadToken();
                if (string.IsNullOrWhiteSpace(token))
                {
                    Console.Error.WriteLine("No token.");
                    return;
                }

                var client = new MadApiClient(url, token);
                var session = await client.GetSessionById(id);

                if (session is null)
                {
                    Console.WriteLine(json ? "null" : "(session not found)");
                    return;
                }

                if (json)
                {
                    Console.WriteLine(JsonSerializer.Serialize(session, MadJsonContext.Default.SessionResponse));
                    return;
                }

                Console.WriteLine("Session Details:");
                Console.WriteLine($"Id         : {session.Id}");
                Console.WriteLine($"UserId     : {session.UserId}");
                Console.WriteLine($"Client     : {session.ClientIdentifier}");
                Console.WriteLine($"Use        : {session.TokenUse}");
                Console.WriteLine($"Revoked    : {session.IsRevoked}");
                Console.WriteLine($"Expires At : {session.ExpiresAt:u}");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Failed to retrieve session {id}.");
                Console.Error.WriteLine(ex.Message);
            }
        }, adminUrl, adminToken, sessionId, jsonOut);

        return cmd;
    }

    private static Command IntrospectTokenCommand()
    {
        var cmd = new Command("introspect", "Introspect a token via the admin introspection endpoint");

        var tokenValue = new Option<string>("--token") { IsRequired = true };
        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(tokenValue);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string url, string? bearer, string tokenToInspect, bool json) =>
        {
            try
            {
                bearer ??= AuthUtils.TryLoadToken();
                if (string.IsNullOrWhiteSpace(bearer))
                {
                    Console.Error.WriteLine("No admin token available.");
                    return;
                }

                var client = new MadApiClient(url, bearer);
                var result = await client.IntrospectTokenAsAdmin(tokenToInspect);

                if (result is null)
                {
                    Console.Error.WriteLine("No response or token invalid.");
                    return;
                }

                if (json)
                {
                    Console.WriteLine(JsonSerializer.Serialize(result, MadJsonContext.Default.DictionaryStringObject));
                    return;
                }

                // Pretty-print
                Console.WriteLine("Token Claims:");
                Console.WriteLine(new string('-', 50));
                foreach (var kvp in result)
                {
                    if (kvp.Value is JsonElement j && j.ValueKind == JsonValueKind.Array)
                    {
                        Console.WriteLine($"{kvp.Key,-20}: [ {string.Join(", ", j.EnumerateArray().Select(x => x.ToString()))} ]");
                    }
                    else
                    {
                        Console.WriteLine($"{kvp.Key,-20}: {kvp.Value}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Failed to introspect token.");
                Console.Error.WriteLine(ex.Message);
            }
        }, adminUrl, adminToken, tokenValue, jsonOut);

        return cmd;
    }

    private static Command ListByUserCommand()
    {
        var cmd = new Command("list-by-user", "List sessions for a specific user");

        var userId = new Option<string>("--user-id") { IsRequired = true };
        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(userId);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string url, string? token, string uid, bool json) =>
        {
            try
            {
                token ??= AuthUtils.TryLoadToken();
                if (string.IsNullOrWhiteSpace(token))
                {
                    Console.Error.WriteLine("No token.");
                    return;
                }

                var client = new MadApiClient(url, token);
                var sessions = await client.ListSessionsForUser(uid);

                if (sessions is null || sessions.Count == 0)
                {
                    Console.WriteLine(json ? "[]" : "(no sessions)");
                    return;
                }

                if (json)
                {
                    Console.WriteLine(JsonSerializer.Serialize(sessions, MadJsonContext.Default.ListSessionResponse));
                    return;
                }

                Console.WriteLine($"{"Id",-36}  {"UserId",-36}  {"Use",-5}  {"Revoked",-7}  Expires At");
                Console.WriteLine(new string('-', 120));
                foreach (var s in sessions)
                {
                    Console.WriteLine($"{s.Id,-36}  {s.UserId,-36}  {s.TokenUse,-5}  {s.IsRevoked,-7}  {s.ExpiresAt:u}");
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Failed to list sessions for user {uid}.");
                Console.Error.WriteLine(ex.Message);
            }
        }, adminUrl, adminToken, userId, jsonOut);

        return cmd;
    }

    private static Command RevokeCommand()
    {
        var cmd = new Command("revoke", "Revoke a session by its token ID (jti)");

        var jti = new Option<string>("--id") { IsRequired = true };
        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(jti);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string url, string? token, string jti, bool json) =>
        {
            try
            {
                token ??= AuthUtils.TryLoadToken();
                if (string.IsNullOrWhiteSpace(token))
                {
                    var err = new ErrorResponse(false, "No token.");
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    return;
                }

                var client = new MadApiClient(url, token);
                var ok = await client.RevokeSession(jti);

                if (json)
                {
                    if (ok)
                    {
                        var msg = new MessageResponse(true, $"Revoked session '{jti}'");
                        Console.WriteLine(JsonSerializer.Serialize(msg, MadJsonContext.Default.MessageResponse));
                    }
                    else
                    {
                        var err = new ErrorResponse(false, $"Failed to revoke session '{jti}'");
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    }
                }
                else
                {
                    Console.WriteLine(ok
                        ? $"Revoked session '{jti}'"
                        : $"Failed to revoke session '{jti}'");
                }
            }
            catch (Exception ex)
            {
                if (json)
                {
                    var err = new ErrorResponse(false, ex.Message);
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                }
                else
                {
                    Console.Error.WriteLine($"Error while revoking session '{jti}':");
                    Console.Error.WriteLine(ex.Message);
                }
            }
        }, adminUrl, adminToken, jti, jsonOut);

        return cmd;
    }

    private static Command PurgeCommand()
    {
        var cmd = new Command("purge", "Purge sessions by age or status");

        var seconds = new Option<int>("--older-than", "Purge sessions older than N seconds") { IsRequired = true };
        var purgeExpired = new Option<bool>("--expired", "Include expired sessions") { IsRequired = false };
        var purgeRevoked = new Option<bool>("--revoked", "Include revoked sessions") { IsRequired = false };
        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(seconds);
        cmd.AddOption(purgeExpired);
        cmd.AddOption(purgeRevoked);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (int older, bool expired, bool revoked, string url, string? token, bool json) =>
        {
            try
            {
                token ??= AuthUtils.TryLoadToken();
                if (string.IsNullOrWhiteSpace(token))
                {
                    var err = new ErrorResponse(false, "No token.");
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    return;
                }

                var client = new MadApiClient(url, token);
                var ok = await client.PurgeSessions(older, expired, revoked);

                if (json)
                {
                    if (ok)
                    {
                        var msg = new MessageResponse(true, "Session purge completed.");
                        Console.WriteLine(JsonSerializer.Serialize(msg, MadJsonContext.Default.MessageResponse));
                    }
                    else
                    {
                        var err = new ErrorResponse(false, "Session purge failed.");
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    }
                }
                else
                {
                    Console.WriteLine(ok ? "Session purge completed." : "Session purge failed.");
                }
            }
            catch (Exception ex)
            {
                if (json)
                {
                    var err = new ErrorResponse(false, ex.Message);
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                }
                else
                {
                    Console.Error.WriteLine("An error occurred during session purge:");
                    Console.Error.WriteLine(ex.Message);
                }
            }
        }, seconds, purgeExpired, purgeRevoked, adminUrl, adminToken, jsonOut);

        return cmd;
    }
}
