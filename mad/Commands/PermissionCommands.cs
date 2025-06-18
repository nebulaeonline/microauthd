using mad.Common;
using mad.Http;
using madTypes.Api.Requests;
using madTypes.Api.Responses;
using System.CommandLine;
using System.Text.Json;

namespace mad.Commands;

internal static class PermissionCommands
{
    public static Command Build()
    {
        var cmd = new Command("permission", "Manage permissions");

        cmd.AddCommand(CreatePermissionCommand());
        cmd.AddCommand(UpdatePermissionCommand());
        cmd.AddCommand(ListPermissionsCommand());
        cmd.AddCommand(GetPermissionByIdCommand());
        cmd.AddCommand(DeletePermissionCommand());
        cmd.AddCommand(AssignPermissionCommand());
        cmd.AddCommand(RemovePermissionCommand());
        cmd.AddCommand(ListPermissionsForRoleCommand());
        cmd.AddCommand(ListPermissionsForUserCommand());
        cmd.AddCommand(CheckAccessCommand());

        return cmd;
    }

    private static Command CreatePermissionCommand()
    {
        var cmd = new Command("create", "Create a new permission");
        var name = new Option<string>("--name") { IsRequired = true };
        
        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(name);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string url, string? token, string name, bool jsonOut) =>
        {
            try
            {
                token ??= AuthUtils.TryLoadToken();
                if (string.IsNullOrWhiteSpace(token))
                {
                    var err = new ErrorResponse(false, "No token. Use --admin-token or run `mad session login`.");
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    return;
                }

                var client = new MadApiClient(url, token);
                var result = await client.CreatePermission(new CreatePermissionRequest { Name = name });

                if (result is null)
                {
                    if (jsonOut)
                    {
                        var err = new ErrorResponse(false, "Failed to create permission.");
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    }
                    else
                    {
                        Console.Error.WriteLine("Failed to create permission.");
                    }
                    return;
                }

                if (jsonOut)
                {
                    Console.WriteLine(JsonSerializer.Serialize(result, MadJsonContext.Default.PermissionObject));
                }
                else
                {
                    Console.WriteLine($"Created permission {result.Name} with ID: {result.Id}");
                }
            }
            catch (Exception ex)
            {
                if (jsonOut)
                {
                    var err = new ErrorResponse(false, $"Exception: {ex.Message}");
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                }
                else
                {
                    Console.Error.WriteLine("Error creating permission.");
                    Console.Error.WriteLine(ex.Message);
                }
            }
        }, adminUrl, adminToken, name, jsonOut);

        return cmd;
    }

    private static Command UpdatePermissionCommand()
    {
        var cmd = new Command("update", "Update a permission");

        var id = new Option<string>("--id") { IsRequired = true };
        var name = new Option<string?>("--name", "New name");

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(id);
        cmd.AddOption(name);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string url, string? token, string id, string? newName, bool json) =>
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

                if (newName is null)
                {
                    var err = new ErrorResponse(false, "You must provide at least one field to update.");
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    return;
                }

                var client = new MadApiClient(url, token);
                var existing = await client.GetPermissionById(id);

                if (existing is null)
                {
                    var err = new ErrorResponse(false, $"Permission '{id}' not found.");
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    return;
                }

                if (newName != null) existing.Name = newName;

                var updated = await client.UpdatePermission(id, existing);
                if (updated is null)
                {
                    var err = new ErrorResponse(false, "Update failed.");
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    return;
                }

                if (json)
                {
                    Console.WriteLine(JsonSerializer.Serialize(updated, MadJsonContext.Default.PermissionObject));
                }
                else
                {
                    Console.WriteLine($"Permission updated: {updated.Name}");
                }
            }
            catch (Exception ex)
            {
                var err = new ErrorResponse(false, $"Unexpected error: {ex.Message}");
                Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
            }
        }, adminUrl, adminToken, id, name, jsonOut);

        return cmd;
    }

    private static Command ListPermissionsCommand()
    {
        var cmd = new Command("list", "List all permissions");

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
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    return;
                }

                var client = new MadApiClient(url, token);
                var perms = await client.ListPermissions();

                if (perms is null || perms.Count == 0)
                {
                    if (json)
                    {
                        Console.WriteLine("[]");
                    }
                    else
                    {
                        Console.WriteLine("(no permissions)");
                    }
                    return;
                }

                if (json)
                {
                    Console.WriteLine(JsonSerializer.Serialize(perms, MadJsonContext.Default.ListPermissionObject));
                }
                else
                {
                    Console.WriteLine($"{"Id",-36}  {"Name",-20}");
                    Console.WriteLine(new string('-', 100));
                    foreach (var p in perms)
                        Console.WriteLine($"{p.Id,-36}  {p.Name,-20}");
                }
            }
            catch (Exception ex)
            {
                if (json)
                {
                    var err = new ErrorResponse(false, $"Exception: {ex.Message}");
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                }
                else
                {
                    Console.Error.WriteLine("Error listing permissions.");
                    Console.Error.WriteLine(ex.Message);
                }
            }
        }, adminUrl, adminToken, jsonOut);

        return cmd;
    }

    private static Command GetPermissionByIdCommand()
    {
        var cmd = new Command("get", "Get permission by ID");

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
                var permission = await client.GetPermissionById(id);

                if (permission is null)
                {
                    var err = new ErrorResponse(false, $"Permission '{id}' not found.");
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    return;
                }

                if (json)
                {
                    Console.WriteLine(JsonSerializer.Serialize(permission, MadJsonContext.Default.PermissionObject));
                }
                else
                {
                    Console.WriteLine($"Id:   {permission.Id}");
                    Console.WriteLine($"Name: {permission.Name}");
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

    private static Command DeletePermissionCommand()
    {
        var cmd = new Command("delete", "Delete a permission");

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
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    return;
                }

                var client = new MadApiClient(url, token);
                var ok = await client.DeletePermission(id);

                if (json)
                {
                    if (ok)
                    {
                        var msg = new MessageResponse(true, $"Deleted permission {id}");
                        Console.WriteLine(JsonSerializer.Serialize(msg, MadJsonContext.Default.MessageResponse));
                    }
                    else
                    {
                        var err = new ErrorResponse(false, $"Failed to delete {id}");
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    }
                }
                else
                {
                    Console.WriteLine(ok
                        ? $"Deleted permission {id}"
                        : $"Failed to delete {id}");
                }
            }
            catch (Exception ex)
            {
                if (json)
                {
                    var err = new ErrorResponse(false, $"Exception: {ex.Message}");
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                }
                else
                {
                    Console.Error.WriteLine($"Error deleting permission {id}.");
                    Console.Error.WriteLine(ex.Message);
                }
            }
        }, adminUrl, adminToken, id, jsonOut);

        return cmd;
    }

    private static Command AssignPermissionCommand()
    {
        var cmd = new Command("assign", "Assign permissions to a role");

        var roleId = new Option<string>("--role-id") { IsRequired = true };
        var permIds = new Option<string>("--permission-id") { IsRequired = true };
        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(roleId);
        cmd.AddOption(permIds);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string url, string? token, string rid, string pid, bool json) =>
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
                var ok = await client.AssignPermissionsToRole(rid, pid);

                if (json)
                {
                    if (ok)
                    {
                        var msg = new MessageResponse(true, "Permissions assigned.");
                        Console.WriteLine(JsonSerializer.Serialize(msg, MadJsonContext.Default.MessageResponse));
                    }
                    else
                    {
                        var err = new ErrorResponse(false, "Failed to assign.");
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    }
                }
                else
                {
                    Console.WriteLine(ok ? "Permissions assigned." : "Failed to assign.");
                }
            }
            catch (Exception ex)
            {
                var err = new ErrorResponse(false, $"Error assigning permission {pid} to role {rid}: {ex.Message}");
                if (json)
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                else
                {
                    Console.Error.WriteLine(err.Message);
                }
            }
        }, adminUrl, adminToken, roleId, permIds, jsonOut);

        return cmd;
    }

    private static Command RemovePermissionCommand()
    {
        var cmd = new Command("remove", "Remove permission from a role");

        var roleId = new Option<string>("--role-id") { IsRequired = true };
        var permId = new Option<string>("--permission-id") { IsRequired = true };

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(roleId);
        cmd.AddOption(permId);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string url, string? token, string rid, string pid, bool json) =>
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
                var ok = await client.RemovePermissionFromRole(rid, pid);

                if (json)
                {
                    if (ok)
                    {
                        var msg = new MessageResponse(true, "Permission removed.");
                        Console.WriteLine(JsonSerializer.Serialize(msg, MadJsonContext.Default.MessageResponse));
                    }
                    else
                    {
                        var err = new ErrorResponse(false, "Failed to remove permission.");
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    }
                }
                else
                {
                    Console.WriteLine(ok ? "Permission removed." : "Failed to remove.");
                }
            }
            catch (Exception ex)
            {
                var err = new ErrorResponse(false, $"Error removing permission {pid} from role {rid}: {ex.Message}");
                if (json)
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                else
                {
                    Console.Error.WriteLine($"Error removing permission {pid} from role {rid}.");
                    Console.Error.WriteLine(ex.Message);
                }
            }
        }, adminUrl, adminToken, roleId, permId, jsonOut);

        return cmd;
    }

    private static Command ListPermissionsForRoleCommand()
    {
        var cmd = new Command("list-for-role", "List permissions for a role");
        var roleId = new Option<string>("--role-id") { IsRequired = true };
        
        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(roleId);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string url, string? token, string rid, bool asJson) =>
        {
            try
            {
                token ??= AuthUtils.TryLoadToken();
                if (string.IsNullOrWhiteSpace(token))
                {
                    var err = new ErrorResponse(false, "No token. Use --admin-token or run `mad session login`.");
                    if (asJson)
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    else
                        Console.Error.WriteLine(err.Message);
                    return;
                }

                var client = new MadApiClient(url, token);
                var perms = await client.ListPermissionsForRole(rid);

                if (perms == null || perms.Count == 0)
                {
                    Console.WriteLine(asJson ? "[]" : "(no permissions)");
                    return;
                }

                if (asJson)
                {
                    Console.WriteLine(JsonSerializer.Serialize(perms, MadJsonContext.Default.ListPermissionObject));
                }
                else
                {
                    Console.WriteLine($"{"Id",-36}  {"Name",-20}");
                    Console.WriteLine(new string('-', 100));
                    foreach (var p in perms)
                    {
                        Console.WriteLine($"{p.Id,-36}  {p.Name,-20}");
                    }
                }
            }
            catch (Exception ex)
            {
                var err = new ErrorResponse(false, $"Error listing permissions for role: {ex.Message}");
                if (asJson)
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                else
                {
                    Console.Error.WriteLine(err.Message);
                }
            }
        }, adminUrl, adminToken, roleId, jsonOut);

        return cmd;
    }

    /// <summary>
    /// Creates a command that lists the effective permissions for a specified user.
    /// </summary>
    /// <remarks>This command retrieves and displays the permissions assigned to a user, either in a
    /// human-readable format or as a JSON array, depending on the specified options. The command requires a user ID and
    /// supports additional options for specifying the admin URL, authentication token, and output format.</remarks>
    /// <returns>A <see cref="Command"/> instance configured to list the effective permissions for a user.</returns>
    private static Command ListPermissionsForUserCommand()
    {
        var cmd = new Command("list-for-user", "List effective permissions for a user");

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
                    var err = new ErrorResponse(false, "No token. Use --admin-token or run `mad session login`.");
                    if (json)
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    else
                        Console.Error.WriteLine(err.Message);
                    return;
                }

                var client = new MadApiClient(url, token);
                var perms = await client.ListPermissionsForUser(uid);

                if (perms is null || perms.Count == 0)
                {
                    Console.WriteLine(json ? "[]" : "(no permissions)");
                    return;
                }

                if (json)
                {
                    Console.WriteLine(JsonSerializer.Serialize(perms, MadJsonContext.Default.ListPermissionObject));
                }
                else
                {
                    Console.WriteLine($"{"Id",-36}  Name");
                    Console.WriteLine(new string('-', 100));
                    foreach (var p in perms)
                        Console.WriteLine($"{p.Id,-36}  {p.Name}");
                }
            }
            catch (Exception ex)
            {
                var err = new ErrorResponse(false, $"Error listing permissions for user {uid}: {ex.Message}");
                if (json)
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                else
                {
                    Console.Error.WriteLine(err.Message);
                }
            }
        }, adminUrl, adminToken, userId, jsonOut);

        return cmd;
    }

    private static Command CheckAccessCommand()
    {
        var cmd = new Command("check-access", "Check if a user has a specific permission");

        var userId = new Option<string>("--user-id") { IsRequired = true };
        var permId = new Option<string>("--permission-id") { IsRequired = true };
        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(userId);
        cmd.AddOption(permId);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string url, string? token, string uid, string pid, bool json) =>
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
                var access = await client.CheckAccess(uid, pid);

                if (json)
                {
                    var result = new MessageResponse(true, access
                        ? "User has permission."
                        : "User does NOT have permission.");
                    Console.WriteLine(JsonSerializer.Serialize(result, MadJsonContext.Default.MessageResponse));
                }
                else
                {
                    Console.WriteLine(access
                        ? "User has permission."
                        : "User does NOT have permission.");
                }
            }
            catch (Exception ex)
            {
                var err = new ErrorResponse(false, $"Error checking access for user {uid} and permission {pid}: {ex.Message}");
                if (json)
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                else
                {
                    Console.Error.WriteLine($"Error checking access for user {uid} and permission {pid}.");
                    Console.Error.WriteLine(ex.Message);
                }
            }
        }, adminUrl, adminToken, userId, permId, jsonOut);

        return cmd;
    }
}