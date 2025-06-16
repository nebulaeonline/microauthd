using System.CommandLine;
using mad.Common;
using mad.Http;
using mad.Api.Requests;

namespace mad.Commands;

internal static class ClientCommands
{
    public static Command Build()
    {
        var cmd = new Command("client", "Manage OIDC clients");

        cmd.AddCommand(CreateClientCommand());
        cmd.AddCommand(ListClientsCommand());
        cmd.AddCommand(DeleteClientCommand());

        cmd.AddCommand(AssignScopesCommand());
        cmd.AddCommand(ListScopesCommand());
        cmd.AddCommand(RemoveScopeCommand());

        return cmd;
    }

    private static Command CreateClientCommand()
    {
        var cmd = new Command("create", "Create a new OIDC client");

        var clientId = new Option<string>("--client-id") { IsRequired = true };
        var secret = new Option<string?>("--secret", description: "Client secret to use (omit to auto-generate)");
        var genLen = new Option<int?>("--gen-password", description: "Generate a random secret of the given length");
        var name = new Option<string?>("--display-name", () => string.Empty);

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;

        cmd.AddOption(clientId);
        cmd.AddOption(secret);
        cmd.AddOption(genLen);
        cmd.AddOption(name);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);

        cmd.SetHandler(async (string url, string? token, string id, string? s, int? gen, string? disp) =>
        {
            token ??= AuthUtils.TryLoadToken();
            if (string.IsNullOrWhiteSpace(token))
            {
                Console.Error.WriteLine("No token. Use --admin-token or run `mad session login`.");
                return;
            }

            var actualSecret = s;

            if (gen.HasValue)
            {
                actualSecret = AuthUtils.GeneratePassword(gen.Value);
                Console.WriteLine($"Generated client secret: {actualSecret}");
            }

            if (string.IsNullOrWhiteSpace(actualSecret))
            {
                Console.Error.WriteLine("Client secret is required (use --secret or --gen-password)");
                return;
            }

            var client = new MadApiClient(url, token);
            var result = await client.CreateClient(new CreateClientRequest
            {
                ClientId = id,
                ClientSecret = actualSecret,
                DisplayName = disp
            });

            Console.WriteLine(result);
        }, adminUrl, adminToken, clientId, secret, genLen, name);

        return cmd;
    }

    private static Command ListClientsCommand()
    {
        var cmd = new Command("list", "List all active clients");
        
        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;

        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);

        cmd.SetHandler(async (string url, string? token) =>
        {
            token ??= AuthUtils.TryLoadToken();
            if (string.IsNullOrWhiteSpace(token))
            {
                Console.Error.WriteLine("No token.");
                return;
            }

            var client = new MadApiClient(url, token);
            var clients = await client.ListClients();

            Console.WriteLine($"{"Id",-36}  {"Client Id",-20}  Display Name");
            Console.WriteLine(new string('-', 100));

            foreach (var c in clients)
                Console.WriteLine($"{c.Id,-36} {c.ClientId,-20} {c.DisplayName}");
        }, adminUrl, adminToken);

        return cmd;
    }

    private static Command DeleteClientCommand()
    {
        var cmd = new Command("delete", "Deactivate a client");
        var id = new Option<string>("--id") { IsRequired = true };
        cmd.AddOption(id);

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;

        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);

        cmd.SetHandler(async (string url, string? token, string id) =>
        {
            token ??= AuthUtils.TryLoadToken();
            if (string.IsNullOrWhiteSpace(token))
            {
                Console.Error.WriteLine("No token.");
                return;
            }

            var client = new MadApiClient(url, token);
            var ok = await client.DeleteClient(id);
            Console.WriteLine(ok ? $"Deleted client '{id}'" : $"Failed to delete '{id}'");
        }, adminUrl, adminToken, id);

        return cmd;
    }

    private static Command AssignScopesCommand()
    {
        var cmd = new Command("assign-scope", "Assign scopes to a client");

        var clientId = new Option<string>("--client-id") { IsRequired = true };
        var scopeIds = new Option<List<string>>("--scope-id") { IsRequired = true, AllowMultipleArgumentsPerToken = true };

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;

        cmd.AddOption(clientId);
        cmd.AddOption(scopeIds);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);

        cmd.SetHandler(async (string url, string? token, string cid, List<string> sids) =>
        {
            token ??= AuthUtils.TryLoadToken();
            if (string.IsNullOrWhiteSpace(token))
            {
                Console.Error.WriteLine("No token.");
                return;
            }

            var client = new MadApiClient(url, token);
            var ok = await client.AssignScopesToClient(cid, sids);
            Console.WriteLine(ok ? "Scopes assigned." : "Failed to assign scopes.");
        }, adminUrl, adminToken, clientId, scopeIds);

        return cmd;
    }

    private static Command ListScopesCommand()
    {
        var cmd = new Command("list-scopes", "List scopes for a client");
        var clientId = new Option<string>("--client-id") { IsRequired = true };

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;

        cmd.AddOption(clientId);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);

        cmd.SetHandler(async (string url, string? token, string cid) =>
        {
            token ??= AuthUtils.TryLoadToken();
            if (string.IsNullOrWhiteSpace(token))
            {
                Console.Error.WriteLine("No token.");
                return;
            }

            var client = new MadApiClient(url, token);
            var scopes = await client.ListScopesForClient(cid);

            foreach (var s in scopes)
                Console.WriteLine($"{s.Name,-20} {s.Description}");
        }, adminUrl, adminToken, clientId);

        return cmd;
    }

    private static Command RemoveScopeCommand()
    {
        var cmd = new Command("remove-scope", "Remove a scope from a client");

        var clientId = new Option<string>("--client-id") { IsRequired = true };
        var scopeId = new Option<string>("--scope-id") { IsRequired = true };

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;

        cmd.AddOption(clientId);
        cmd.AddOption(scopeId);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);

        cmd.SetHandler(async (string url, string? token, string cid, string sid) =>
        {
            token ??= AuthUtils.TryLoadToken();
            if (string.IsNullOrWhiteSpace(token))
            {
                Console.Error.WriteLine("No token.");
                return;
            }

            var client = new MadApiClient(url, token);
            var ok = await client.RemoveScopeFromClient(cid, sid);
            Console.WriteLine(ok ? "Scope removed." : "Failed to remove.");
        }, adminUrl, adminToken, clientId, scopeId);

        return cmd;
    }
}
