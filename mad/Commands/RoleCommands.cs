using mad.Common;
using mad.Http;
using madTypes.Api.Requests;
using madTypes.Api.Responses;
using System.CommandLine;
using System.Text.Json;

namespace mad.Commands;

internal static class RoleCommands
{
    public static Command Build()
    {
        var cmd = new Command("role", "Manage roles");

        cmd.AddCommand(CreateRoleCommand());
        cmd.AddCommand(UpdateRoleCommand());
        cmd.AddCommand(ListRolesCommand());
        cmd.AddCommand(GetRoleByIdCommand());
        cmd.AddCommand(DeleteRoleCommand());
        cmd.AddCommand(AssignRoleCommand());
        cmd.AddCommand(UnassignRoleCommand());

        return cmd;
    }

    private static Command CreateRoleCommand()
    {
        var cmd = new Command("create", "Create a new role");

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

        cmd.SetHandler(async (string url, string? token, string roleName, string description, bool jsonOut) =>
        {
            try
            {
                token ??= AuthUtils.TryLoadToken();
                if (string.IsNullOrWhiteSpace(token))
                {
                    var err = new ErrorResponse(false, "No token. Use --admin-token or run `mad session login`.");
                    if (jsonOut)
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    else
                        Console.Error.WriteLine(err.Message);
                    return;
                }

                var client = new MadApiClient(url, token);
                var result = await client.CreateRole(new CreateRoleRequest
                {
                    Name = roleName,
                    Description = description
                });

                if (result is null)
                {
                    var err = new ErrorResponse(false, "Failed to create role.");
                    if (jsonOut)
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    else
                        Console.Error.WriteLine(err.Message);
                    return;
                }

                if (jsonOut)
                {
                    Console.WriteLine(JsonSerializer.Serialize(result, MadJsonContext.Default.RoleObject));
                }
                else
                {
                    Console.WriteLine($"Created role {roleName} with ID: {result.Id}");
                }
            }
            catch (Exception ex)
            {
                var err = new ErrorResponse(false, $"Error creating role {roleName}: {ex.Message}");
                if (jsonOut)
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                else
                {
                    Console.Error.WriteLine(err.Message);
                }
            }
        }, adminUrl, adminToken, name, desc, jsonOut);

        return cmd;
    }

    private static Command UpdateRoleCommand()
    {
        var cmd = new Command("update", "Update a role");

        var id = new Option<string>("--id") { IsRequired = true };
        var name = new Option<string?>("--name", "New name for the role");
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

        cmd.SetHandler(async (string url, string? token, string id, string? name, string? desc, bool json) =>
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

                if (name is null && desc is null)
                {
                    var err = new ErrorResponse(false, "You must provide at least one field to update.");
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    return;
                }

                var client = new MadApiClient(url, token);
                var existing = await client.GetRoleById(id);

                if (existing is null)
                {
                    var err = new ErrorResponse(false, $"Role '{id}' not found.");
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    return;
                }

                if (name is not null) existing.Name = name;
                if (desc is not null) existing.Description = desc;

                var updated = await client.UpdateRole(id, existing);
                if (updated is null)
                {
                    var err = new ErrorResponse(false, "Update failed.");
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    return;
                }

                if (json)
                {
                    Console.WriteLine(JsonSerializer.Serialize(updated, MadJsonContext.Default.RoleObject));
                }
                else
                {
                    Console.WriteLine($"Role updated: {updated.Name}");
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

    private static Command ListRolesCommand()
    {
        var cmd = new Command("list", "List all roles");

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
                    var err = new ErrorResponse(false, "No token. Use --admin-token or run `mad session login`.");
                    if (json)
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    else
                        Console.Error.WriteLine(err.Message);
                    return;
                }

                var client = new MadApiClient(url, token);
                var roles = await client.ListRoles();

                if (roles is null || roles.Count == 0)
                {
                    Console.WriteLine(json ? "[]" : "(no roles)");
                    return;
                }

                if (json)
                {
                    Console.WriteLine(JsonSerializer.Serialize(roles, MadJsonContext.Default.ListRoleObject));
                }
                else
                {
                    Console.WriteLine($"{"Id",-36}  {"Name",-20}  {"Protected",-9}  Description");
                    Console.WriteLine(new string('-', 100));
                    foreach (var r in roles)
                    {
                        Console.WriteLine($"{r.Id,-36}  {r.Name,-20}  {r.IsProtected,-9}  {r.Description}");
                    }
                }
            }
            catch (Exception ex)
            {
                var err = new ErrorResponse(false, $"Error listing roles: {ex.Message}");
                if (json)
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                else
                    Console.Error.WriteLine(err.Message);
            }
        }, adminUrl, adminToken, jsonOut);

        return cmd;
    }

    private static Command GetRoleByIdCommand()
    {
        var cmd = new Command("get", "Get role by ID");

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
                var role = await client.GetRoleById(id);

                if (role is null)
                {
                    var err = new ErrorResponse(false, $"Role '{id}' not found.");
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    return;
                }

                if (json)
                {
                    Console.WriteLine(JsonSerializer.Serialize(role, MadJsonContext.Default.RoleObject));
                }
                else
                {
                    Console.WriteLine($"Id:          {role.Id}");
                    Console.WriteLine($"Name:        {role.Name}");
                    Console.WriteLine($"Description: {role.Description}");
                    Console.WriteLine($"Protected:   {role.IsProtected}");
                }
            }
            catch (Exception ex)
            {
                var err = new ErrorResponse(false, ex.Message);
                Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
            }
        }, adminUrl, adminToken, id, jsonOut);

        return cmd;
    }

    private static Command DeleteRoleCommand()
    {
        var cmd = new Command("delete", "Delete a role");

        var id = new Option<string>("--id") { IsRequired = true };

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(id);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string url, string? token, string roleId, bool json) =>
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
                var ok = await client.DeleteRole(roleId);

                if (json)
                {
                    if (ok)
                    {
                        var msg = new MessageResponse(true, $"Deleted role {roleId}");
                        Console.WriteLine(JsonSerializer.Serialize(msg, MadJsonContext.Default.MessageResponse));
                    }
                    else
                    {
                        var err = new ErrorResponse(false, $"Failed to delete role {roleId}");
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    }
                }
                else
                {
                    Console.WriteLine(ok
                        ? $"Deleted role {roleId}"
                        : $"Failed to delete role {roleId}");
                }
            }
            catch (Exception ex)
            {
                var err = new ErrorResponse(false, $"Error deleting role {roleId}: {ex.Message}");
                if (json)
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                else
                    Console.Error.WriteLine(err.Message);
            }
        }, adminUrl, adminToken, id, jsonOut);

        return cmd;
    }

    private static Command AssignRoleCommand()
    {
        var cmd = new Command("assign", "Assign a role to a user");

        var uid = new Option<string>("--user-id") { IsRequired = true };
        var rid = new Option<string>("--role-id") { IsRequired = true };

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(uid);
        cmd.AddOption(rid);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string url, string? token, string userId, string roleId, bool json) =>
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
                var ok = await client.AssignRole(userId, roleId);

                if (json)
                {
                    if (ok)
                    {
                        var msg = new MessageResponse(true, $"Assigned role {roleId} to user {userId}");
                        Console.WriteLine(JsonSerializer.Serialize(msg, MadJsonContext.Default.MessageResponse));
                    }
                    else
                    {
                        var err = new ErrorResponse(false, $"Failed to assign role {roleId} to user {userId}");
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    }
                }
                else
                {
                    Console.WriteLine(ok
                        ? $"Assigned role {roleId} to user {userId}"
                        : $"Failed to assign role {roleId} to user {userId}");
                }
            }
            catch (Exception ex)
            {
                var err = new ErrorResponse(false, $"Error assigning role {roleId} to user {userId}: {ex.Message}");
                if (json)
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                else
                    Console.Error.WriteLine(err.Message);
            }
        }, adminUrl, adminToken, uid, rid, jsonOut);

        return cmd;
    }

    private static Command UnassignRoleCommand()
    {
        var cmd = new Command("unassign", "Remove a role from a user");

        var uid = new Option<string>("--user-id") { IsRequired = true };
        var rid = new Option<string>("--role-id") { IsRequired = true };

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(uid);
        cmd.AddOption(rid);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string url, string? token, string userId, string roleId, bool json) =>
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
                var ok = await client.UnassignRole(userId, roleId);

                if (json)
                {
                    if (ok)
                    {
                        var msg = new MessageResponse(true, $"Removed role {roleId} from user {userId}");
                        Console.WriteLine(JsonSerializer.Serialize(msg, MadJsonContext.Default.MessageResponse));
                    }
                    else
                    {
                        var err = new ErrorResponse(false, $"Failed to remove role {roleId} from user {userId}");
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    }
                }
                else
                {
                    Console.WriteLine(ok
                        ? $"Removed role {roleId} from user {userId}"
                        : $"Failed to remove role {roleId} from user {userId}");
                }
            }
            catch (Exception ex)
            {
                var err = new ErrorResponse(false, $"Error removing role {roleId} from user {userId}: {ex.Message}");
                if (json)
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                else
                    Console.Error.WriteLine(err.Message);
            }
        }, adminUrl, adminToken, uid, rid, jsonOut);

        return cmd;
    }
}