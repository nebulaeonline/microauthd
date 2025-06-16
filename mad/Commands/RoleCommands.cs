using System.CommandLine;
using madTypes.Api.Requests;
using mad.Common;
using mad.Http;

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

        cmd.AddOption(name);
        cmd.AddOption(desc);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);

        cmd.SetHandler(async (string url, string? token, string roleName, string description) =>
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

            Console.WriteLine(result);
        }, adminUrl, adminToken, name, desc);

        return cmd;
    }

    private static Command ListRolesCommand()
    {
        var cmd = new Command("list", "List all roles");

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;

        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);

        cmd.SetHandler(async (string url, string? token) =>
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
                Console.WriteLine("(no roles)");
                return;
            }

            Console.WriteLine($"{"Id",-36}  {"Name",-20}  {"Protected",-9}  Description");
            Console.WriteLine(new string('-', 100));
            foreach (var r in roles)
            {
                Console.WriteLine($"{r.Id,-36}  {r.Name,-20}  {r.IsProtected,-9}  {r.Description}");
            }
        }, adminUrl, adminToken);

        return cmd;
    }

    private static Command DeleteRoleCommand()
    {
        var cmd = new Command("delete", "Delete (deactivate) a role");

        var id = new Option<string>("--id") { IsRequired = true };

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;

        cmd.AddOption(id);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);

        cmd.SetHandler(async (string url, string? token, string roleId) =>
        {
            token ??= AuthUtils.TryLoadToken();
            if (string.IsNullOrWhiteSpace(token))
            {
                Console.Error.WriteLine("No token. Use --admin-token or run `mad session login`.");
                return;
            }

            var client = new MadApiClient(url, token);
            var ok = await client.DeleteRole(roleId);
            Console.WriteLine(ok ? $"Deleted role '{roleId}'" : $"Failed to delete role '{roleId}'");
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
            token ??= AuthUtils.TryLoadToken();
            if (string.IsNullOrWhiteSpace(token))
            {
                Console.Error.WriteLine("No token. Use --admin-token or run `mad session login`.");
                return;
            }

            var client = new MadApiClient(url, token);
            var ok = await client.AssignRole(userId, roleId);
            Console.WriteLine(ok ? $"Assigned role '{roleId}' to user '{userId}'"
                                 : $"Failed to assign role '{roleId}' to user '{userId}'");
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
            token ??= AuthUtils.TryLoadToken();
            if (string.IsNullOrWhiteSpace(token))
            {
                Console.Error.WriteLine("No token. Use --admin-token or run `mad session login`.");
                return;
            }

            var client = new MadApiClient(url, token);
            var ok = await client.UnassignRole(userId, roleId);
            Console.WriteLine(ok ? $"Removed role '{roleId}' from user '{userId}'"
                                 : $"Failed to remove role '{roleId}' from user '{userId}'");
        }, adminUrl, adminToken, uid, rid);

        return cmd;
    }
}