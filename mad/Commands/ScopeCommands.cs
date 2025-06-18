using mad.Common;
using mad.Http;
using madTypes.Api.Requests;
using madTypes.Api.Responses;
using madTypes.Api.Common;
using System.CommandLine;
using System.Text.Json;

namespace mad.Commands;

internal static class ScopeCommands
{
    public static Command Build()
    {
        var cmd = new Command("scope", "Manage scopes");

        cmd.AddCommand(CreateScopeCommand());
        cmd.AddCommand(UpdateScopeCommand());
        cmd.AddCommand(ListScopesCommand());
        cmd.AddCommand(GetScopeByIdCommand());
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
                    var err = new ErrorResponse(false, "No token. Use --admin-token or `mad session login`.");
                    if (jsonOut)
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    else
                        Console.Error.WriteLine(err.Message);
                    return;
                }

                var client = new MadApiClient(url, token);
                var result = await client.CreateScope(new ScopeObject
                {
                    Name = scopeName,
                    Description = description
                });

                if (result is null)
                {
                    var err = new ErrorResponse(false, "Failed to create scope.");
                    if (jsonOut)
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    else
                        Console.Error.WriteLine(err.Message);
                    return;
                }

                if (jsonOut)
                {
                    Console.WriteLine(JsonSerializer.Serialize(result, MadJsonContext.Default.ScopeObject));
                }
                else
                {
                    Console.WriteLine($"Created scope {scopeName} with ID: {result.Id}");
                }
            }
            catch (Exception ex)
            {
                var err = new ErrorResponse(false, $"Error creating scope '{scopeName}': {ex.Message}");
                if (jsonOut)
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                else
                    Console.Error.WriteLine(err.Message);
            }
        }, adminUrl, adminToken, name, desc, jsonOut);

        return cmd;
    }

    private static Command UpdateScopeCommand()
    {
        var cmd = new Command("update", "Update a scope");

        var id = new Option<string>("--id") { IsRequired = true };
        var name = new Option<string?>("--name", "New name");
        var description = new Option<string?>("--description", "New description");

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(id);
        cmd.AddOption(name);
        cmd.AddOption(description);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string url, string? token, string id, string? newName, string? newDesc, bool json) =>
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

                if (newName is null && newDesc is null)
                {
                    var err = new ErrorResponse(false, "You must provide at least one field to update.");
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    return;
                }

                var client = new MadApiClient(url, token);
                var existing = await client.GetScopeById(id);

                if (existing is null)
                {
                    var err = new ErrorResponse(false, $"Scope '{id}' not found.");
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    return;
                }

                var updatedInput = new ScopeObject
                {
                    Id = existing.Id,
                    Name = newName ?? existing.Name,
                    Description = newDesc ?? existing.Description,
                    CreatedAt = existing.CreatedAt,
                    IsActive = existing.IsActive
                };

                var updated = await client.UpdateScope(id, updatedInput);
                if (updated is null)
                {
                    var err = new ErrorResponse(false, "Update failed.");
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    return;
                }

                if (json)
                {
                    Console.WriteLine(JsonSerializer.Serialize(updated, MadJsonContext.Default.ScopeObject));
                }
                else
                {
                    Console.WriteLine($"Scope updated: {updated.Name}");
                }
            }
            catch (Exception ex)
            {
                var err = new ErrorResponse(false, $"Unexpected error: {ex.Message}");
                Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
            }
        }, adminUrl, adminToken, id, name, description, jsonOut);

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
                    var err = new ErrorResponse(false, "No token. Use --admin-token or `mad session login`.");
                    if (json)
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    else
                        Console.Error.WriteLine(err.Message);
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
                    Console.WriteLine(JsonSerializer.Serialize(scopes, MadJsonContext.Default.ListScopeObject));
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
                var err = new ErrorResponse(false, $"Error retrieving scopes: {ex.Message}");
                if (json)
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                else
                    Console.Error.WriteLine(err.Message);
            }
        }, adminUrl, adminToken, jsonOut);

        return cmd;
    }

    private static Command GetScopeByIdCommand()
    {
        var cmd = new Command("get", "Get scope by ID");

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
                var scope = await client.GetScopeById(id);

                if (scope is null)
                {
                    var err = new ErrorResponse(false, $"Scope '{id}' not found.");
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    return;
                }

                if (json)
                {
                    Console.WriteLine(JsonSerializer.Serialize(scope, MadJsonContext.Default.ScopeObject));
                }
                else
                {
                    Console.WriteLine($"Id:          {scope.Id}");
                    Console.WriteLine($"Name:        {scope.Name}");
                    Console.WriteLine($"Description: {scope.Description}");
                    Console.WriteLine($"Created At:  {scope.CreatedAt}");
                    Console.WriteLine($"Active:      {scope.IsActive}");
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

    private static Command DeleteScopeCommand()
    {
        var cmd = new Command("delete", "Delete a scope");

        var id = new Option<string>("--id") { IsRequired = true };
        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(id);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string url, string? token, string scopeId, bool json) =>
        {
            try
            {
                token ??= AuthUtils.TryLoadToken();
                if (string.IsNullOrWhiteSpace(token))
                {
                    var err = new ErrorResponse(false, "No token. Use --admin-token or `mad session login`.");
                    if (json)
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    else
                        Console.Error.WriteLine(err.Message);
                    return;
                }

                var client = new MadApiClient(url, token);
                var ok = await client.DeleteScope(scopeId);

                if (json)
                {
                    if (ok)
                    {
                        var msg = new MessageResponse(true, $"Deleted scope {scopeId}");
                        Console.WriteLine(JsonSerializer.Serialize(msg, MadJsonContext.Default.MessageResponse));
                    }
                    else
                    {
                        var err = new ErrorResponse(false, $"Failed to delete scope {scopeId}");
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    }
                }
                else
                {
                    Console.WriteLine(ok ? $"Deleted scope {scopeId}" : $"Failed to delete scope {scopeId}");
                }
            }
            catch (Exception ex)
            {
                var err = new ErrorResponse(false, $"Error deleting scope {scopeId}: {ex.Message}");
                if (json)
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                else
                    Console.Error.WriteLine(err.Message);
            }
        }, adminUrl, adminToken, id, jsonOut);

        return cmd;
    }

    private static Command AssignToUserCommand()
    {
        var cmd = new Command("assign-to-user", "Assign scopes to a user");

        var uid = new Option<string>("--user-id") { IsRequired = true };
        var scopeIds = new Option<List<string>>("--scope-id") { IsRequired = true, AllowMultipleArgumentsPerToken = true };

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(uid);
        cmd.AddOption(scopeIds);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string url, string? token, string userId, List<string> ids, bool json) =>
        {
            try
            {
                token ??= AuthUtils.TryLoadToken();
                if (string.IsNullOrWhiteSpace(token))
                {
                    var err = new ErrorResponse(false, "No token. Use --admin-token or `mad session login`.");
                    if (json)
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    else
                        Console.Error.WriteLine(err.Message);
                    return;
                }

                var client = new MadApiClient(url, token);
                var ok = await client.AssignScopesToUser(userId, ids);

                if (json)
                {
                    if (ok)
                        Console.WriteLine(JsonSerializer.Serialize(new MessageResponse(true, "Scopes assigned."), MadJsonContext.Default.MessageResponse));
                    else
                        Console.WriteLine(JsonSerializer.Serialize(new ErrorResponse(false, "Failed to assign scopes."), MadJsonContext.Default.ErrorResponse));
                }
                else
                {
                    Console.WriteLine(ok ? "Scopes assigned." : "Failed to assign scopes.");
                }
            }
            catch (Exception ex)
            {
                var err = new ErrorResponse(false, $"Error assigning scopes to user: {ex.Message}");
                if (json)
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                else
                    Console.Error.WriteLine(err.Message);
            }
        }, adminUrl, adminToken, uid, scopeIds, jsonOut);

        return cmd;
    }

    private static Command ListForUserCommand()
    {
        var cmd = new Command("list-for-user", "List scopes for a user");

        var uid = new Option<string>("--user-id") { IsRequired = true };
        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(uid);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string url, string? token, string userId, bool json) =>
        {
            try
            {
                token ??= AuthUtils.TryLoadToken();
                if (string.IsNullOrWhiteSpace(token))
                {
                    var err = new ErrorResponse(false, "No token. Use --admin-token or `mad session login`.");
                    if (json)
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    else
                        Console.Error.WriteLine(err.Message);
                    return;
                }

                var client = new MadApiClient(url, token);
                var scopes = await client.ListScopesForUser(userId);

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
                    Console.WriteLine($"{"Id",-36}  {"Name",-20}  {"Description"}");
                    Console.WriteLine(new string('-', 100));
                    foreach (var s in scopes)
                        Console.WriteLine($"{s.Id,-36} {s.Name,-20} {s.Description}");
                }
            }
            catch (Exception ex)
            {
                var err = new ErrorResponse(false, $"Error retrieving scopes for user: {ex.Message}");
                if (json)
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                else
                    Console.Error.WriteLine(err.Message);
            }
        }, adminUrl, adminToken, uid, jsonOut);

        return cmd;
    }

    private static Command RemoveFromUserCommand()
    {
        var cmd = new Command("remove-from-user", "Remove a scope from a user");

        var uid = new Option<string>("--user-id") { IsRequired = true };
        var sid = new Option<string>("--scope-id") { IsRequired = true };
        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(uid);
        cmd.AddOption(sid);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string url, string? token, string userId, string scopeId, bool json) =>
        {
            try
            {
                token ??= AuthUtils.TryLoadToken();
                if (string.IsNullOrWhiteSpace(token))
                {
                    var err = new ErrorResponse(false, "No token. Use --admin-token or `mad session login`.");
                    if (json)
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    else
                        Console.Error.WriteLine(err.Message);
                    return;
                }

                var client = new MadApiClient(url, token);
                var ok = await client.RemoveScopeFromUser(userId, scopeId);

                if (json)
                {
                    if (ok)
                    {
                        var res = new MessageResponse(true, $"Scope '{scopeId}' removed from user '{userId}'.");
                        Console.WriteLine(JsonSerializer.Serialize(res, MadJsonContext.Default.MessageResponse));
                    }
                    else
                    {
                        var err = new ErrorResponse(false, $"Failed to remove scope '{scopeId}' from user '{userId}'.");
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    }
                }
                else
                {
                    Console.WriteLine(ok
                        ? $"Scope '{scopeId}' removed from user '{userId}'."
                        : $"Failed to remove scope '{scopeId}' from user '{userId}'.");
                }
            }
            catch (Exception ex)
            {
                var err = new ErrorResponse(false, $"Error removing scope from user: {ex.Message}");
                if (json)
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                else
                    Console.Error.WriteLine(err.Message);
            }
        }, adminUrl, adminToken, uid, sid, jsonOut);

        return cmd;
    }

    private static Command AssignToClientCommand()
    {
        var cmd = new Command("assign-to-client", "Assign scopes to a client");

        var cid = new Option<string>("--client-id") { IsRequired = true };
        var scopeIds = new Option<List<string>>("--scope-id") { IsRequired = true, AllowMultipleArgumentsPerToken = true };
        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(cid);
        cmd.AddOption(scopeIds);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string url, string? token, string clientId, List<string> ids, bool json) =>
        {
            try
            {
                token ??= AuthUtils.TryLoadToken();
                if (string.IsNullOrWhiteSpace(token))
                {
                    var err = new ErrorResponse(false, "No token. Use --admin-token or `mad session login`.");
                    if (json)
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    else
                        Console.Error.WriteLine(err.Message);
                    return;
                }

                var client = new MadApiClient(url, token);
                var ok = await client.AssignScopesToClient(clientId, ids);

                if (json)
                {
                    if (ok)
                    {
                        var res = new MessageResponse(true, $"Scopes assigned to client '{clientId}'.");
                        Console.WriteLine(JsonSerializer.Serialize(res, MadJsonContext.Default.MessageResponse));
                    }
                    else
                    {
                        var err = new ErrorResponse(false, $"Failed to assign scopes to client '{clientId}'.");
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    }
                }
                else
                {
                    Console.WriteLine(ok
                        ? $"Scopes assigned to client '{clientId}'."
                        : $"Failed to assign scopes to client '{clientId}'.");
                }
            }
            catch (Exception ex)
            {
                var err = new ErrorResponse(false, $"Error assigning scopes to client: {ex.Message}");
                if (json)
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                else
                    Console.Error.WriteLine(err.Message);
            }
        }, adminUrl, adminToken, cid, scopeIds, jsonOut);

        return cmd;
    }

    private static Command ListForClientCommand()
    {
        var cmd = new Command("list-for-client", "List scopes for a client");

        var cid = new Option<string>("--client-id") { IsRequired = true };
        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(cid);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string url, string? token, string clientId, bool json) =>
        {
            try
            {
                token ??= AuthUtils.TryLoadToken();
                if (string.IsNullOrWhiteSpace(token))
                {
                    var err = new ErrorResponse(false, "No token. Use --admin-token or `mad session login`.");
                    if (json)
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    else
                        Console.Error.WriteLine(err.Message);
                    return;
                }

                var client = new MadApiClient(url, token);
                var scopes = await client.ListScopesForClient(clientId);

                if (scopes is null || scopes.Count == 0)
                {
                    if (json)
                        Console.WriteLine("[]");
                    else
                        Console.WriteLine("(no scopes)");
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
                var err = new ErrorResponse(false, $"Error retrieving scopes for client: {ex.Message}");
                if (json)
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                else
                    Console.Error.WriteLine(err.Message);
            }
        }, adminUrl, adminToken, cid, jsonOut);

        return cmd;
    }

    private static Command RemoveFromClientCommand()
    {
        var cmd = new Command("remove-from-client", "Remove a scope from a client");

        var cid = new Option<string>("--client-id") { IsRequired = true };
        var sid = new Option<string>("--scope-id") { IsRequired = true };
        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(cid);
        cmd.AddOption(sid);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string url, string? token, string clientId, string scopeId, bool json) =>
        {
            try
            {
                token ??= AuthUtils.TryLoadToken();
                if (string.IsNullOrWhiteSpace(token))
                {
                    var err = new ErrorResponse(false, "No token. Use --admin-token or `mad session login`.");
                    if (json)
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    else
                        Console.Error.WriteLine(err.Message);
                    return;
                }

                var client = new MadApiClient(url, token);
                var ok = await client.RemoveScopeFromClient(clientId, scopeId);

                if (json)
                {
                    if (ok)
                        Console.WriteLine(JsonSerializer.Serialize(new MessageResponse(true, "Scope removed."), MadJsonContext.Default.MessageResponse));
                    else
                        Console.WriteLine(JsonSerializer.Serialize(new ErrorResponse(false, "Failed to remove scope."), MadJsonContext.Default.ErrorResponse));
                }
                else
                {
                    Console.WriteLine(ok ? "Scope removed." : "Failed to remove scope.");
                }
            }
            catch (Exception ex)
            {
                var err = new ErrorResponse(false, $"Error removing scope from client: {ex.Message}");
                if (json)
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                else
                    Console.Error.WriteLine(err.Message);
            }
        }, adminUrl, adminToken, cid, sid, jsonOut);

        return cmd;
    }
}