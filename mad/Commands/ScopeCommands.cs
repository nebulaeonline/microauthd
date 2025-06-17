using mad.Common;
using mad.Http;
using madTypes.Api.Requests;
using madTypes.Api.Responses;
using System.CommandLine;
using System.Text.Json;

namespace mad.Commands;

internal static class ScopeCommands
{
    public static Command Build()
    {
        var cmd = new Command("scope", "Manage scopes");

        cmd.AddCommand(CreateScopeCommand());
        cmd.AddCommand(ListScopesCommand());
        cmd.AddCommand(DeleteScopeCommand());

        cmd.AddCommand(AssignToUserCommand());
        cmd.AddCommand(ListForUserCommand());
        cmd.AddCommand(RemoveFromUserCommand());

        cmd.AddCommand(AssignToClientCommand());
        cmd.AddCommand(ListForClientCommand());
        cmd.AddCommand(RemoveFromClientCommand());

        return cmd;
    }

    private static Command CreateScopeCommand()
    {
        var cmd = new Command("create", "Create a new scope");

        var name = new Option<string>("--name") { IsRequired = true };
        var desc = new Option<string>("--description", () => string.Empty);

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(name);
        cmd.AddOption(desc);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string url, string? token, string scopeName, string description, bool jsonOut) =>
        {
            try
            {
                token ??= AuthUtils.TryLoadToken();
                if (string.IsNullOrWhiteSpace(token))
                {
                    Console.Error.WriteLine("No token. Use --admin-token or `mad session login`.");
                    return;
                }

                var client = new MadApiClient(url, token);
                var result = await client.CreateScope(new ScopeResponse
                {
                    Name = scopeName,
                    Description = description
                });

                if (result is null)
                {
                    Console.Error.WriteLine("Failed to create scope.");
                    return;
                }

                if (jsonOut)
                {
                    Console.WriteLine(JsonSerializer.Serialize(result, MadJsonContext.Default.ScopeResponse));
                }
                else
                {
                    Console.WriteLine($"Created scope {scopeName} with ID: {result.Id}");
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error creating scope '{scopeName}'.");
                Console.Error.WriteLine(ex.Message);
            }
        }, adminUrl, adminToken, name, desc, jsonOut);


        return cmd;
    }

    private static Command ListScopesCommand()
    {
        var cmd = new Command("list", "List all active scopes");

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(jsonOut);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);

        cmd.SetHandler(async (string url, string? token, bool json) =>
        {
            try
            {
                token ??= AuthUtils.TryLoadToken();
                if (string.IsNullOrWhiteSpace(token))
                {
                    Console.Error.WriteLine("No token. Use --admin-token or `mad session login`.");
                    return;
                }

                var client = new MadApiClient(url, token);
                var scopes = await client.ListScopes();

                if (scopes is null || scopes.Count == 0)
                {
                    Console.WriteLine(json ? "[]" : "(no scopes)");
                    return;
                }

                if (json)
                {
                    Console.WriteLine(JsonSerializer.Serialize(scopes, MadJsonContext.Default.ListScopeResponse));
                }
                else
                {
                    Console.WriteLine($"{"Id",-36}  {"Name",-20}  Description");
                    Console.WriteLine(new string('-', 100));

                    foreach (var s in scopes)
                        Console.WriteLine($"{s.Id,-36} {s.Name,-20} {s.Description}");
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error retrieving scopes.");
                Console.Error.WriteLine(ex.Message);
            }
        }, adminUrl, adminToken, jsonOut);

        return cmd;
    }

    private static Command DeleteScopeCommand()
    {
        var cmd = new Command("delete", "Delete a scope");

        var id = new Option<string>("--id") { IsRequired = true };

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;

        cmd.AddOption(id);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);

        cmd.SetHandler(async (string url, string? token, string scopeId) =>
        {
            try
            {
                token ??= AuthUtils.TryLoadToken();
                if (string.IsNullOrWhiteSpace(token))
                {
                    Console.Error.WriteLine("No token. Use --admin-token or `mad session login`.");
                    return;
                }

                var client = new MadApiClient(url, token);
                var ok = await client.DeleteScope(scopeId);
                Console.WriteLine(ok ? $"Deleted scope {scopeId}" : $"Failed to delete scope {scopeId}");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error deleting scope.");
                Console.Error.WriteLine(ex.Message);
            }
        }, adminUrl, adminToken, id);

        return cmd;
    }

    private static Command AssignToUserCommand()
    {
        var cmd = new Command("assign-to-user", "Assign scopes to a user");

        var uid = new Option<string>("--user-id") { IsRequired = true };
        var scopeIds = new Option<List<string>>("--scope-id") { IsRequired = true, AllowMultipleArgumentsPerToken = true };

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;

        cmd.AddOption(uid);
        cmd.AddOption(scopeIds);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);

        cmd.SetHandler(async (string url, string? token, string userId, List<string> ids) =>
        {
            try
            {
                token ??= AuthUtils.TryLoadToken();
                if (string.IsNullOrWhiteSpace(token))
                {
                    Console.Error.WriteLine("No token. Use --admin-token or `mad session login`.");
                    return;
                }

                var client = new MadApiClient(url, token);
                var ok = await client.AssignScopesToUser(userId, ids);
                Console.WriteLine(ok ? "Scopes assigned." : "Failed to assign scopes.");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error assigning scopes to user.");
                Console.Error.WriteLine(ex.Message);
            }
        }, adminUrl, adminToken, uid, scopeIds);

        return cmd;
    }

    private static Command ListForUserCommand()
    {
        var cmd = new Command("list-for-user", "List scopes for a user");

        var uid = new Option<string>("--user-id") { IsRequired = true };

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;

        cmd.AddOption(uid);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);

        cmd.SetHandler(async (string url, string? token, string userId) =>
        {
            try
            {
                token ??= AuthUtils.TryLoadToken();
                if (string.IsNullOrWhiteSpace(token))
                {
                    Console.Error.WriteLine("No token. Use --admin-token or `mad session login`.");
                    return;
                }

                var client = new MadApiClient(url, token);
                var scopes = await client.ListScopesForUser(userId);

                if (scopes is null || scopes.Count == 0)
                {
                    Console.WriteLine("(no scopes)");
                    return;
                }

                Console.WriteLine($"{"Id",-36}  {"Name",-20}  {"Description"}");
                Console.WriteLine(new string('-', 100));

                foreach (var s in scopes)
                    Console.WriteLine($"{s.Id,-36} {s.Name,-20} {s.Description}");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error retrieving scopes for user.");
                Console.Error.WriteLine(ex.Message);
            }
        }, adminUrl, adminToken, uid);

        return cmd;
    }

    private static Command RemoveFromUserCommand()
    {
        var cmd = new Command("remove-from-user", "Remove a scope from a user");

        var uid = new Option<string>("--user-id") { IsRequired = true };
        var sid = new Option<string>("--scope-id") { IsRequired = true };

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;

        cmd.AddOption(uid);
        cmd.AddOption(sid);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);

        cmd.SetHandler(async (string url, string? token, string userId, string scopeId) =>
        {
            try
            {
                token ??= AuthUtils.TryLoadToken();
                if (string.IsNullOrWhiteSpace(token))
                {
                    Console.Error.WriteLine("No token. Use --admin-token or `mad session login`.");
                    return;
                }

                var client = new MadApiClient(url, token);
                var ok = await client.RemoveScopeFromUser(userId, scopeId);
                Console.WriteLine(ok ? "Scope removed." : "Failed to remove scope.");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error removing scope from user.");
                Console.Error.WriteLine(ex.Message);
            }
        }, adminUrl, adminToken, uid, sid);

        return cmd;
    }

    private static Command AssignToClientCommand()
    {
        var cmd = new Command("assign-to-client", "Assign scopes to a client");

        var cid = new Option<string>("--client-id") { IsRequired = true };
        var scopeIds = new Option<List<string>>("--scope-id") { IsRequired = true, AllowMultipleArgumentsPerToken = true };

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;

        cmd.AddOption(cid);
        cmd.AddOption(scopeIds);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);

        cmd.SetHandler(async (string url, string? token, string clientId, List<string> ids) =>
        {
            try
            {
                token ??= AuthUtils.TryLoadToken();
                if (string.IsNullOrWhiteSpace(token))
                {
                    Console.Error.WriteLine("No token. Use --admin-token or `mad session login`.");
                    return;
                }

                var client = new MadApiClient(url, token);
                var ok = await client.AssignScopesToClient(clientId, ids);
                Console.WriteLine(ok ? "Scopes assigned." : "Failed to assign scopes.");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error assigning scopes to client.");
                Console.Error.WriteLine(ex.Message);
            }
        }, adminUrl, adminToken, cid, scopeIds);

        return cmd;
    }

    private static Command ListForClientCommand()
    {
        var cmd = new Command("list-for-client", "List scopes for a client");

        var cid = new Option<string>("--client-id") { IsRequired = true };

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;

        cmd.AddOption(cid);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);

        cmd.SetHandler(async (string url, string? token, string clientId) =>
        {
            try
            {
                token ??= AuthUtils.TryLoadToken();
                if (string.IsNullOrWhiteSpace(token))
                {
                    Console.Error.WriteLine("No token. Use --admin-token or `mad session login`.");
                    return;
                }

                var client = new MadApiClient(url, token);
                var scopes = await client.ListScopesForClient(clientId);

                if (scopes is null || scopes.Count == 0)
                {
                    Console.WriteLine("(no scopes)");
                    return;
                }

                Console.WriteLine($"{"Id",-36} {"Name",-20} Description");
                Console.WriteLine(new string('-', 100));

                foreach (var s in scopes)
                    Console.WriteLine($"{s.Id,-36} {s.Name,-20} {s.Description}");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error retrieving scopes for client.");
                Console.Error.WriteLine(ex.Message);
            }
        }, adminUrl, adminToken, cid);


        return cmd;
    }

    private static Command RemoveFromClientCommand()
    {
        var cmd = new Command("remove-from-client", "Remove a scope from a client");

        var cid = new Option<string>("--client-id") { IsRequired = true };
        var sid = new Option<string>("--scope-id") { IsRequired = true };

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;

        cmd.AddOption(cid);
        cmd.AddOption(sid);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);

        cmd.SetHandler(async (string url, string? token, string clientId, string scopeId) =>
        {
            try
            {
                token ??= AuthUtils.TryLoadToken();
                if (string.IsNullOrWhiteSpace(token))
                {
                    Console.Error.WriteLine("No token. Use --admin-token or `mad session login`.");
                    return;
                }

                var client = new MadApiClient(url, token);
                var ok = await client.RemoveScopeFromClient(clientId, scopeId);
                Console.WriteLine(ok ? "Scope removed." : "Failed to remove scope.");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error removing scope from client.");
                Console.Error.WriteLine(ex.Message);
            }
        }, adminUrl, adminToken, cid, sid);

        return cmd;
    }
}