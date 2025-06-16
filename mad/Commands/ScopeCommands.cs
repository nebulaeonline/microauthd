using System.CommandLine;
using mad.Common;
using mad.Http;
using mad.Api.Responses;
using mad.Api.Requests;

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

        cmd.AddOption(name);
        cmd.AddOption(desc);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);

        cmd.SetHandler(async (string url, string? token, string scopeName, string desc) =>
        {
            token ??= AuthUtils.TryLoadToken();
            if (string.IsNullOrWhiteSpace(token))
            {
                Console.Error.WriteLine("No token. Use --admin-token or `mad session login`.");
                return;
            }

            var client = new MadApiClient(url, token);
            var result = await client.CreateScope(new ScopeResponse { Name = scopeName, Description = desc });
            Console.WriteLine(result);
        }, adminUrl, adminToken, name, desc);

        return cmd;
    }

    private static Command ListScopesCommand()
    {
        var cmd = new Command("list", "List all active scopes");

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;

        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);

        cmd.SetHandler(async (string url, string? token) =>
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
                Console.WriteLine("(no scopes)");
                return;
            }

            Console.WriteLine($"{"Id",-36}  {"Name",-20}  Description");
            Console.WriteLine(new string('-', 100));

            foreach (var s in scopes)
                Console.WriteLine($"{s.Id,-36} {s.Name,-20} {s.Description}");
        }, adminUrl, adminToken);

        return cmd;
    }

    private static Command DeleteScopeCommand()
    {
        var cmd = new Command("delete", "Delete (deactivate) a scope");

        var id = new Option<string>("--id") { IsRequired = true };

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;

        cmd.AddOption(id);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);

        cmd.SetHandler(async (string url, string? token, string scopeId) =>
        {
            token ??= AuthUtils.TryLoadToken();
            if (string.IsNullOrWhiteSpace(token))
            {
                Console.Error.WriteLine("No token. Use --admin-token or `mad session login`.");
                return;
            }

            var client = new MadApiClient(url, token);
            var ok = await client.DeleteScope(scopeId);
            Console.WriteLine(ok ? $"Deleted scope '{scopeId}'" : $"Failed to delete scope '{scopeId}'");
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
            token ??= AuthUtils.TryLoadToken();
            if (string.IsNullOrWhiteSpace(token))
            {
                Console.Error.WriteLine("No token. Use --admin-token or `mad session login`.");
                return;
            }

            var client = new MadApiClient(url, token);
            var ok = await client.AssignScopesToUser(userId, ids);
            Console.WriteLine(ok ? "Scopes assigned." : "Failed to assign scopes.");
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
            token ??= AuthUtils.TryLoadToken();
            if (string.IsNullOrWhiteSpace(token))
            {
                Console.Error.WriteLine("No token. Use --admin-token or `mad session login`.");
                return;
            }

            var client = new MadApiClient(url, token);
            var scopes = await client.ListScopesForUser(userId);
            foreach (var s in scopes)
                Console.WriteLine($"{s.Name,-20} {s.Description}");
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
            token ??= AuthUtils.TryLoadToken();
            if (string.IsNullOrWhiteSpace(token))
            {
                Console.Error.WriteLine("No token. Use --admin-token or `mad session login`.");
                return;
            }

            var client = new MadApiClient(url, token);
            var ok = await client.RemoveScopeFromUser(userId, scopeId);
            Console.WriteLine(ok ? "Scope removed." : "Failed to remove scope.");
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
            token ??= AuthUtils.TryLoadToken();
            if (string.IsNullOrWhiteSpace(token))
            {
                Console.Error.WriteLine("No token. Use --admin-token or `mad session login`.");
                return;
            }

            var client = new MadApiClient(url, token);
            var ok = await client.AssignScopesToClient(clientId, ids);
            Console.WriteLine(ok ? "Scopes assigned." : "Failed to assign scopes.");
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
            token ??= AuthUtils.TryLoadToken();
            if (string.IsNullOrWhiteSpace(token))
            {
                Console.Error.WriteLine("No token. Use --admin-token or `mad session login`.");
                return;
            }

            var client = new MadApiClient(url, token);
            var scopes = await client.ListScopesForClient(clientId);
            foreach (var s in scopes)
                Console.WriteLine($"{s.Name,-20} {s.Description}");
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
            token ??= AuthUtils.TryLoadToken();
            if (string.IsNullOrWhiteSpace(token))
            {
                Console.Error.WriteLine("No token. Use --admin-token or `mad session login`.");
                return;
            }

            var client = new MadApiClient(url, token);
            var ok = await client.RemoveScopeFromClient(clientId, scopeId);
            Console.WriteLine(ok ? "Scope removed." : "Failed to remove scope.");
        }, adminUrl, adminToken, cid, sid);

        return cmd;
    }
}