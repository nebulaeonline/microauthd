using mad.Common;
using mad.Http;
using madTypes.Api.Common;
using madTypes.Api.Requests;
using madTypes.Api.Responses;
using System.CommandLine;
using System.Text.Json;

namespace mad.Commands;

internal static class ClientCommands
{
    public static Command Build()
    {
        var cmd = new Command("client", "Manage OIDC clients");

        cmd.AddCommand(CreateClientCommand());
        cmd.AddCommand(UpdateClientCommand());
        cmd.AddCommand(ListClientsCommand());
        cmd.AddCommand(GetClientByIdCommand());
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
        var audience = new Option<string?>("--audience", "Audience for the client (optional. Defaults to 'microauthd'") { IsRequired = false };

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(clientId);
        cmd.AddOption(secret);
        cmd.AddOption(genLen);
        cmd.AddOption(name);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(audience);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string url, string? token, string id, string? s, int? gen, string? disp, string? aud, bool jsonOut) =>
        {
            try
            {
                token ??= AuthUtils.TryLoadToken();
                if (string.IsNullOrWhiteSpace(token))
                {
                    var error = new ErrorResponse(false, "No token. Use --admin-token or run `mad session login`.");
                    if (jsonOut)
                        Console.WriteLine(JsonSerializer.Serialize(error, MadJsonContext.Default.ErrorResponse));
                    else
                        Console.Error.WriteLine(error.Message);
                    return;
                }

                var actualSecret = s;

                if (gen.HasValue)
                {
                    actualSecret = AuthUtils.GeneratePassword(gen.Value);
                    if (!jsonOut)
                        Console.WriteLine($"Generated client secret: {actualSecret}");
                }

                if (string.IsNullOrWhiteSpace(actualSecret))
                {
                    var error = new ErrorResponse(false, "Client secret is required (use --secret or --gen-password).");
                    if (jsonOut)
                        Console.WriteLine(JsonSerializer.Serialize(error, MadJsonContext.Default.ErrorResponse));
                    else
                        Console.Error.WriteLine(error.Message);
                    return;
                }

                var client = new MadApiClient(url, token);
                var result = await client.CreateClient(new CreateClientRequest
                {
                    ClientId = id,
                    ClientSecret = actualSecret,
                    DisplayName = disp,
                    Audience = aud ?? "microauthd"
                });

                if (result is null)
                {
                    var error = new ErrorResponse(false, "Client creation failed.");
                    if (jsonOut)
                        Console.WriteLine(JsonSerializer.Serialize(error, MadJsonContext.Default.ErrorResponse));
                    else
                        Console.Error.WriteLine(error.Message);
                    return;
                }

                if (jsonOut)
                {
                    Console.WriteLine(JsonSerializer.Serialize(result, MadJsonContext.Default.ClientObject));
                }
                else
                {
                    Console.WriteLine($"Created client {id} with ID: {result.Id}");
                }
            }
            catch (Exception ex)
            {
                var error = new ErrorResponse(false, $"Unhandled exception: {ex.Message}");
                if (jsonOut)
                    Console.WriteLine(JsonSerializer.Serialize(error, MadJsonContext.Default.ErrorResponse));
                else
                {
                    Console.Error.WriteLine("Error creating client.");
                    Console.Error.WriteLine(ex.Message);
                }
            }
        }, adminUrl, adminToken, clientId, secret, genLen, name, audience, jsonOut);

        return cmd;
    }

    private static Command UpdateClientCommand()
    {
        var cmd = new Command("update", "Update a client");

        var id = new Option<string>("--id") { IsRequired = true };
        var clientId = new Option<string?>("--client-id", "New client identifier");
        var displayName = new Option<string?>("--display-name", "New display name");
        var active = new Option<bool?>("--is-active", "Set active status (true/false)");
        var audience = new Option<string?>("--audience", "New audience for the client (optional, defaults to 'microauthd')");

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(id);
        cmd.AddOption(clientId);
        cmd.AddOption(displayName);
        cmd.AddOption(active);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(jsonOut);
        cmd.AddOption(audience);

        cmd.SetHandler(async (
            string url, string? token, string id,
            string? newClientId, string? newName, bool? newStatus, string? aud, bool json) =>
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

                if (newClientId is null && newName is null && newStatus is null && audience is null)
                {
                    var err = new ErrorResponse(false, "You must provide at least one field to update.");
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    return;
                }

                var client = new MadApiClient(url, token);
                var existing = await client.GetClientById(id);
                if (existing is null)
                {
                    var err = new ErrorResponse(false, $"Client '{id}' not found.");
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    return;
                }

                var updatedInput = new ClientObject
                {
                    Id = existing.Id,
                    ClientId = newClientId ?? existing.ClientId,
                    DisplayName = newName ?? existing.DisplayName,
                    IsActive = newStatus ?? existing.IsActive,
                    CreatedAt = existing.CreatedAt,
                    Audience = aud ?? existing.Audience
                };

                var updated = await client.UpdateClient(id, updatedInput);
                if (updated is null)
                {
                    var err = new ErrorResponse(false, "Update failed.");
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    return;
                }

                if (json)
                {
                    Console.WriteLine(JsonSerializer.Serialize(updated, MadJsonContext.Default.ClientObject));
                }
                else
                {
                    Console.WriteLine($"Client updated: {updated.ClientId}");
                }
            }
            catch (Exception ex)
            {
                var err = new ErrorResponse(false, $"Unexpected error: {ex.Message}");
                Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
            }
        }, adminUrl, adminToken, id, clientId, displayName, active, audience, jsonOut);

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
                    var error = new ErrorResponse(false, "No token. Use --admin-token or run `mad session login`.");
                    if (json)
                        Console.WriteLine(JsonSerializer.Serialize(error, MadJsonContext.Default.ErrorResponse));
                    else
                        Console.Error.WriteLine(error.Message);
                    return;
                }

                var client = new MadApiClient(url, token);
                var clients = await client.ListClients();

                if (clients is null || clients.Count == 0)
                {
                    if (json)
                        Console.WriteLine("[]");
                    else
                        Console.WriteLine("(no clients)");
                    return;
                }

                if (json)
                {
                    Console.WriteLine(JsonSerializer.Serialize(clients, MadJsonContext.Default.ListClientObject));
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
                var error = new ErrorResponse(false, $"Exception while listing clients: {ex.Message}");
                if (json)
                    Console.WriteLine(JsonSerializer.Serialize(error, MadJsonContext.Default.ErrorResponse));
                else
                {
                    Console.Error.WriteLine("Failed to retrieve client list.");
                    Console.Error.WriteLine(ex.Message);
                }
            }
        }, adminUrl, adminToken, jsonOut);

        return cmd;
    }

    private static Command GetClientByIdCommand()
    {
        var cmd = new Command("get", "Get client by ID");

        var id = new Option<string>("--id") { IsRequired = true };
        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(id);
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
                    var err = new ErrorResponse(false, "No token.");
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    return;
                }

                var client = new MadApiClient(url, token);
                var obj = await client.GetClientById(id);

                if (obj is null)
                {
                    var err = new ErrorResponse(false, $"Client '{id}' not found.");
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    return;
                }

                if (json)
                {
                    Console.WriteLine(JsonSerializer.Serialize(obj, MadJsonContext.Default.ClientObject));
                }
                else
                {
                    Console.WriteLine($"Id:           {obj.Id}");
                    Console.WriteLine($"ClientId:     {obj.ClientId}");
                    Console.WriteLine($"Display Name: {obj.DisplayName}");
                    Console.WriteLine($"Active:       {obj.IsActive}");
                    Console.WriteLine($"Created At:   {obj.CreatedAt}");
                }
            }
            catch (Exception ex)
            {
                var err = new ErrorResponse(false, $"Unexpected error: {ex.Message}");
                Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
            }
        }, adminUrl, adminToken, id, jsonOut);

        return cmd;
    }

    private static Command DeleteClientCommand()
    {
        var cmd = new Command("delete", "Delete a client");

        var id = new Option<string>("--id") { IsRequired = true };
        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(id);
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
                    var err = new ErrorResponse(false, "No token. Use --admin-token or run `mad session login`.");
                    if (json)
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    else
                        Console.Error.WriteLine(err.Message);
                    return;
                }

                var client = new MadApiClient(url, token);
                var ok = await client.DeleteClient(id);

                if (ok)
                {
                    var msg = new MessageResponse(true, $"Deleted client id {id}");
                    if (json)
                        Console.WriteLine(JsonSerializer.Serialize(msg, MadJsonContext.Default.MessageResponse));
                    else
                        Console.WriteLine(msg.Message);
                }
                else
                {
                    var err = new ErrorResponse(false, $"Failed to delete client id {id}");
                    if (json)
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    else
                        Console.Error.WriteLine(err.Message);
                }
            }
            catch (Exception ex)
            {
                var err = new ErrorResponse(false, $"Exception deleting client id {id}: {ex.Message}");
                if (json)
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                else
                {
                    Console.Error.WriteLine($"Error deleting client id {id}.");
                    Console.Error.WriteLine(ex.Message);
                }
            }
        }, adminUrl, adminToken, id, jsonOut);

        return cmd;
    }

    private static Command AssignScopesCommand()
    {
        var cmd = new Command("assign-scope", "Assign scopes to a client");

        var clientId = new Option<string>("--client-id") { IsRequired = true };
        var scopeIds = new Option<List<string>>("--scope-id")
        {
            IsRequired = true,
            AllowMultipleArgumentsPerToken = true
        };

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(clientId);
        cmd.AddOption(scopeIds);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string url, string? token, string cid, List<string> sids, bool json) =>
        {
            try
            {
                token ??= AuthUtils.TryLoadToken();
                if (string.IsNullOrWhiteSpace(token))
                {
                    var err = new ErrorResponse(false, "No token. Use --admin-token or run `mad session login`.");
                    if (json)
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    else
                        Console.Error.WriteLine(err.Message);
                    return;
                }

                var client = new MadApiClient(url, token);
                var ok = await client.AssignScopesToClient(cid, sids);

                if (ok)
                {
                    var msg = new MessageResponse(true, "Scopes assigned.");
                    if (json)
                        Console.WriteLine(JsonSerializer.Serialize(msg, MadJsonContext.Default.MessageResponse));
                    else
                        Console.WriteLine(msg.Message);
                }
                else
                {
                    var err = new ErrorResponse(false, "Failed to assign scopes.");
                    if (json)
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    else
                        Console.Error.WriteLine(err.Message);
                }
            }
            catch (Exception ex)
            {
                var err = new ErrorResponse(false, $"Exception while assigning scopes: {ex.Message}");
                if (json)
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                else
                {
                    Console.Error.WriteLine("Error assigning scopes to client.");
                    Console.Error.WriteLine(ex.Message);
                }
            }
        }, adminUrl, adminToken, clientId, scopeIds, jsonOut);

        return cmd;
    }

    private static Command ListScopesCommand()
    {
        var cmd = new Command("list-scopes", "List scopes for a client");

        var clientId = new Option<string>("--client-id") { IsRequired = true };
        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(clientId);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string url, string? token, string cid, bool json) =>
        {
            try
            {
                token ??= AuthUtils.TryLoadToken();
                if (string.IsNullOrWhiteSpace(token))
                {
                    var err = new ErrorResponse(false, "No token. Use --admin-token or run `mad session login`.");
                    if (json)
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    else
                        Console.Error.WriteLine(err.Message);
                    return;
                }

                var client = new MadApiClient(url, token);
                var scopes = await client.ListScopesForClient(cid);

                if (scopes is null || scopes.Count == 0)
                {
                    Console.WriteLine(json ? "[]" : "(no scopes)");
                    return;
                }

                if (json)
                {
                    Console.WriteLine(JsonSerializer.Serialize(scopes, MadJsonContext.Default.ListScopeObject));
                }
                else
                {
                    Console.WriteLine($"{"Id",-36} {"Name",-20} Description");
                    Console.WriteLine(new string('-', 100));
                    foreach (var s in scopes)
                        Console.WriteLine($"{s.Id,-36} {s.Name,-20} {s.Description}");
                }
            }
            catch (Exception ex)
            {
                var err = new ErrorResponse(false, $"Exception while listing scopes: {ex.Message}");
                if (json)
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                else
                {
                    Console.Error.WriteLine($"Failed to list scopes for client {cid}.");
                    Console.Error.WriteLine(ex.Message);
                }
            }
        }, adminUrl, adminToken, clientId, jsonOut);

        return cmd;
    }

    private static Command RemoveScopeCommand()
    {
        var cmd = new Command("remove-scope", "Remove a scope from a client");

        var clientId = new Option<string>("--client-id") { IsRequired = true };
        var scopeId = new Option<string>("--scope-id") { IsRequired = true };

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(clientId);
        cmd.AddOption(scopeId);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string url, string? token, string cid, string sid, bool json) =>
        {
            try
            {
                token ??= AuthUtils.TryLoadToken();
                if (string.IsNullOrWhiteSpace(token))
                {
                    var err = new ErrorResponse(false, "No token.");
                    if (json)
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    else
                        Console.Error.WriteLine(err.Message);
                    return;
                }

                var client = new MadApiClient(url, token);
                var ok = await client.RemoveScopeFromClient(cid, sid);

                if (json)
                {
                    if (ok)
                    {
                        var result = new MessageResponse(true, "Scope removed.");
                        Console.WriteLine(JsonSerializer.Serialize(result, MadJsonContext.Default.MessageResponse));
                    }
                    else
                    {
                        var result = new ErrorResponse(false, "Failed to remove scope.");
                        Console.WriteLine(JsonSerializer.Serialize(result, MadJsonContext.Default.ErrorResponse));
                    }
                }
                else
                {
                    Console.WriteLine(ok ? "Scope removed." : "Failed to remove.");
                }
            }
            catch (Exception ex)
            {
                var err = new ErrorResponse(false, $"Error removing scope {sid} from client {cid}: {ex.Message}");
                if (json)
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                else
                {
                    Console.Error.WriteLine($"Error removing scope {sid} from client {cid}.");
                    Console.Error.WriteLine(ex.Message);
                }
            }
        }, adminUrl, adminToken, clientId, scopeId, jsonOut);

        return cmd;
    }
}
