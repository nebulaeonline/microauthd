using mad.Common;
using mad.Http;
using madTypes.Api.Requests;
using System.CommandLine;
using System.Text.Json;

namespace mad.Commands;

internal static class RoleCommands
{
    public static Command Build()
    {
        var cmd = new Command("role", "Manage roles");

        cmd.AddCommand(CreateRoleCommand());
        cmd.AddCommand(ListRolesCommand());
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
                    Console.Error.WriteLine("No token. Use --admin-token or run `mad session login`.");
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
                    Console.Error.WriteLine("Failed to create role.");
                    return;
                }

                if (jsonOut)
                {
                    Console.WriteLine(JsonSerializer.Serialize(result, MadJsonContext.Default.RoleResponse));
                }
                else
                {
                    Console.WriteLine($"Created role {roleName} with ID: {result.Id}");
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error creating role {roleName}.");
                Console.Error.WriteLine(ex.Message);
            }
        }, adminUrl, adminToken, name, desc, jsonOut);

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
                    Console.Error.WriteLine("No token. Use --admin-token or run `mad session login`.");
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
                    Console.WriteLine(JsonSerializer.Serialize(roles, MadJsonContext.Default.ListRoleResponse));
                    return;
                }

                Console.WriteLine($"{"Id",-36}  {"Name",-20}  {"Protected",-9}  Description");
                Console.WriteLine(new string('-', 100));
                foreach (var r in roles)
                {
                    Console.WriteLine($"{r.Id,-36}  {r.Name,-20}  {r.IsProtected,-9}  {r.Description}");
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error listing roles.");
                Console.Error.WriteLine(ex.Message);
            }
        }, adminUrl, adminToken, jsonOut);

        return cmd;
    }

    private static Command DeleteRoleCommand()
    {
        var cmd = new Command("delete", "Delete a role");

        var id = new Option<string>("--id") { IsRequired = true };

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;

        cmd.AddOption(id);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);

        cmd.SetHandler(async (string url, string? token, string roleId) =>
        {
            try
            {
                token ??= AuthUtils.TryLoadToken();
                if (string.IsNullOrWhiteSpace(token))
                {
                    Console.Error.WriteLine("No token. Use --admin-token or run `mad session login`.");
                    return;
                }

                var client = new MadApiClient(url, token);
                var ok = await client.DeleteRole(roleId);
                Console.WriteLine(ok ? $"Deleted role {roleId}" : $"Failed to delete role {roleId}");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error deleting role {roleId}.");
                Console.Error.WriteLine(ex.Message);
            }
        }, adminUrl, adminToken, id);

        return cmd;
    }

    private static Command AssignRoleCommand()
    {
        var cmd = new Command("assign", "Assign a role to a user");

        var uid = new Option<string>("--user-id") { IsRequired = true };
        var rid = new Option<string>("--role-id") { IsRequired = true };

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;

        cmd.AddOption(uid);
        cmd.AddOption(rid);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);

        cmd.SetHandler(async (string url, string? token, string userId, string roleId) =>
        {
            try
            {
                token ??= AuthUtils.TryLoadToken();
                if (string.IsNullOrWhiteSpace(token))
                {
                    Console.Error.WriteLine("No token. Use --admin-token or run `mad session login`.");
                    return;
                }

                var client = new MadApiClient(url, token);
                var ok = await client.AssignRole(userId, roleId);
                Console.WriteLine(ok ? $"Assigned role {roleId} to user {userId}"
                                     : $"Failed to assign role {roleId} to user {userId}");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error assigning role {roleId} to user {userId}.");
                Console.Error.WriteLine(ex.Message);
            }
        }, adminUrl, adminToken, uid, rid);

        return cmd;
    }

    private static Command UnassignRoleCommand()
    {
        var cmd = new Command("unassign", "Remove a role from a user");

        var uid = new Option<string>("--user-id") { IsRequired = true };
        var rid = new Option<string>("--role-id") { IsRequired = true };

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;

        cmd.AddOption(uid);
        cmd.AddOption(rid);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);

        cmd.SetHandler(async (string url, string? token, string userId, string roleId) =>
        {
            try
            {
                token ??= AuthUtils.TryLoadToken();
                if (string.IsNullOrWhiteSpace(token))
                {
                    Console.Error.WriteLine("No token. Use --admin-token or run `mad session login`.");
                    return;
                }

                var client = new MadApiClient(url, token);
                var ok = await client.UnassignRole(userId, roleId);
                Console.WriteLine(ok ? $"Removed role {roleId} from user {userId}"
                                     : $"Failed to remove role {roleId} from user {userId}");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error removing role {roleId} from user {userId}.");
                Console.Error.WriteLine(ex.Message);
            }
        }, adminUrl, adminToken, uid, rid);

        return cmd;
    }
}