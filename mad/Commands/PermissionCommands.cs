using mad.Common;
using mad.Http;
using madTypes.Api.Requests;
using System.CommandLine;
using System.Text.Json;

namespace mad.Commands;

internal static class PermissionCommands
{
    public static Command Build()
    {
        var cmd = new Command("permission", "Manage permissions");

        cmd.AddCommand(CreatePermissionCommand());
        cmd.AddCommand(ListPermissionsCommand());
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
                    Console.Error.WriteLine("No token.");
                    return;
                }

                var client = new MadApiClient(url, token);
                var result = await client.CreatePermission(new CreatePermissionRequest { Name = name });

                if (result is null)
                {
                    Console.Error.WriteLine("Failed to create permission.");
                    return;
                }

                if (jsonOut)
                {
                    Console.WriteLine(JsonSerializer.Serialize(result, MadJsonContext.Default.PermissionResponse));
                }
                else
                {
                    Console.WriteLine($"Created permission {result.Name} with ID: {result.Id}");
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error creating permission.");
                Console.Error.WriteLine(ex.Message);
            }
        }, adminUrl, adminToken, name, jsonOut);


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
                    Console.Error.WriteLine("No token.");
                    return;
                }

                var client = new MadApiClient(url, token);
                var perms = await client.ListPermissions();

                if (perms is null || perms.Count == 0)
                {
                    Console.WriteLine(json ? "[]" : "(no permissions)");
                    return;
                }

                if (json)
                {
                    Console.WriteLine(JsonSerializer.Serialize(perms, MadJsonContext.Default.ListPermissionResponse));
                    return;
                }

                Console.WriteLine($"{"Id",-36}  {"Name",-20}");
                Console.WriteLine(new string('-', 100));
                foreach (var p in perms)
                    Console.WriteLine($"{p.Id,-36}  {p.Name,-20}");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error listing permissions.");
                Console.Error.WriteLine(ex.Message);
            }
        }, adminUrl, adminToken, jsonOut);

        return cmd;
    }

    private static Command DeletePermissionCommand()
    {
        var cmd = new Command("delete", "Delete a permission");
        var id = new Option<string>("--id") { IsRequired = true };
        
        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;

        cmd.AddOption(id);
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
                var ok = await client.DeletePermission(id);
                Console.WriteLine(ok ? $"Deleted permission {id}" : $"Failed to delete {id}");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error deleting permission {id}.");
                Console.Error.WriteLine(ex.Message);
            }
        }, adminUrl, adminToken, id);

        return cmd;
    }

    private static Command AssignPermissionCommand()
    {
        var cmd = new Command("assign", "Assign permissions to a role");

        var roleId = new Option<string>("--role-id") { IsRequired = true };
        var permIds = new Option<string>("--permission-id") { IsRequired = true };

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;

        cmd.AddOption(roleId);
        cmd.AddOption(permIds);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);

        cmd.SetHandler(async (string url, string? token, string rid, string pid) =>
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
                var ok = await client.AssignPermissionsToRole(rid, pid);
                Console.WriteLine(ok ? "Permissions assigned." : "Failed to assign.");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error assigning permission {pid} to role {rid}.");
                Console.Error.WriteLine(ex.Message);
            }
        }, adminUrl, adminToken, roleId, permIds);

        return cmd;
    }

    private static Command RemovePermissionCommand()
    {
        var cmd = new Command("remove", "Remove permission from a role");

        var roleId = new Option<string>("--role-id") { IsRequired = true };
        var permId = new Option<string>("--permission-id") { IsRequired = true };

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        cmd.AddOption(roleId);
        cmd.AddOption(permId);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);

        cmd.SetHandler(async (string url, string? token, string rid, string pid) =>
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
                var ok = await client.RemovePermissionFromRole(rid, pid);
                Console.WriteLine(ok ? "Permission removed." : "Failed to remove.");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error removing permission {pid} from role {rid}.");
                Console.Error.WriteLine(ex.Message);
            }
        }, adminUrl, adminToken, roleId, permId);


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
                    Console.Error.WriteLine("No token.");
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
                    Console.WriteLine(JsonSerializer.Serialize(perms, MadJsonContext.Default.ListPermissionResponse));
                    return;
                }

                Console.WriteLine($"{"Id",-36}  {"Name",-20}");
                Console.WriteLine(new string('-', 100));
                foreach (var p in perms)
                {
                    Console.WriteLine($"{p.Id,-36}  {p.Name,-20}");
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error listing permissions for role: {ex.Message}");
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
                    Console.Error.WriteLine("No token.");
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
                    Console.WriteLine(JsonSerializer.Serialize(perms, MadJsonContext.Default.ListPermissionResponse));
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
                Console.Error.WriteLine($"Error listing permissions for user {uid}.");
                Console.Error.WriteLine(ex.Message);
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

        cmd.AddOption(userId);
        cmd.AddOption(permId);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);

        cmd.SetHandler(async (string url, string? token, string uid, string pid) =>
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
                var access = await client.CheckAccess(uid, pid);

                Console.WriteLine(access ? "User has permission." : "User does NOT have permission.");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error checking access for user {uid} and permission {pid}.");
                Console.Error.WriteLine(ex.Message);
            }
        }, adminUrl, adminToken, userId, permId);


        return cmd;
    }
}