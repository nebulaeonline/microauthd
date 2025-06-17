using mad.Common;
using mad.Http;
using madTypes.Api.Requests;
using System.CommandLine;
using System.Text.Json;

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
        var secret = new Option<string?>("--secret", "Client secret to use (omit to auto-generate)");
        var genLen = new Option<int?>("--gen-password", "Generate a random secret of the given length");
        var name = new Option<string?>("--display-name", () => string.Empty);

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(clientId);
        cmd.AddOption(secret);
        cmd.AddOption(genLen);
        cmd.AddOption(name);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string url, string? token, string id, string? s, int? gen, string? disp, bool jsonOut) =>
        {
            try
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
                    Console.Error.WriteLine("Client secret is required (use --secret or --gen-password).");
                    return;
                }

                var client = new MadApiClient(url, token);
                var result = await client.CreateClient(new CreateClientRequest
                {
                    ClientId = id,
                    ClientSecret = actualSecret,
                    DisplayName = disp
                });

                if (result is null)
                {
                    Console.Error.WriteLine("Client creation failed.");
                    return;
                }

                if (jsonOut)
                {
                    Console.WriteLine(JsonSerializer.Serialize(result, MadJsonContext.Default.ClientResponse));
                }
                else
                {
                    Console.WriteLine($"Created client {id} with ID: {result.Id}");
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error creating client.");
                Console.Error.WriteLine(ex.Message);
            }
        }, adminUrl, adminToken, clientId, secret, genLen, name, jsonOut);

        return cmd;
    }

    private static Command ListClientsCommand()
    {
        var cmd = new Command("list", "List all active clients");
        
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
                var clients = await client.ListClients();

                if (clients is null || clients.Count == 0)
                {
                    Console.WriteLine(json ? "[]" : "(no clients)");
                    return;
                }

                if (json)
                {
                    Console.WriteLine(JsonSerializer.Serialize(clients, MadJsonContext.Default.ListClientResponse));
                }
                else
                {
                    Console.WriteLine($"{"Id",-36}  {"Client Identifier",-24}  {"Active",-8}  Display Name");
                    Console.WriteLine(new string('-', 100));
                    foreach (var c in clients)
                    {
                        Console.WriteLine($"{c.Id,-36}  {c.ClientId,-24}  {c.IsActive,-8}  {c.DisplayName}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Failed to retrieve client list.");
                Console.Error.WriteLine(ex.Message);
            }
        }, adminUrl, adminToken, jsonOut);

        return cmd;
    }

    private static Command DeleteClientCommand()
    {
        var cmd = new Command("delete", "Delete a client");
        var id = new Option<string>("--id") { IsRequired = true };
        cmd.AddOption(id);

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;

        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);

        cmd.SetHandler(async (string url, string? token, string id) =>
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
                var ok = await client.DeleteClient(id);

                Console.WriteLine(ok
                    ? $"Deleted client id {id}"
                    : $"Failed to delete client id {id}");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error deleting client id {id}.");
                Console.Error.WriteLine(ex.Message);
            }
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
            try
            {
                token ??= AuthUtils.TryLoadToken();
                if (string.IsNullOrWhiteSpace(token))
                {
                    Console.Error.WriteLine("No token.");
                    return;
                }

                var client = new MadApiClient(url, token);
                var ok = await client.AssignScopesToClient(cid, sids);

                Console.WriteLine(ok
                    ? "Scopes assigned."
                    : "Failed to assign scopes.");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error assigning scopes to client.");
                Console.Error.WriteLine(ex.Message);
            }
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
            try
            {
                token ??= AuthUtils.TryLoadToken();
                if (string.IsNullOrWhiteSpace(token))
                {
                    Console.Error.WriteLine("No token.");
                    return;
                }

                var client = new MadApiClient(url, token);
                var scopes = await client.ListScopesForClient(cid);

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
                Console.Error.WriteLine($"Failed to list scopes for client {cid}.");
                Console.Error.WriteLine(ex.Message);
            }
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
            try
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
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error removing scope {sid} from client {cid}.");
                Console.Error.WriteLine(ex.Message);
            }
        }, adminUrl, adminToken, clientId, scopeId);

        return cmd;
    }
}
