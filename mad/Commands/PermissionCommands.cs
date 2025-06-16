using System.CommandLine;
using mad.Api.Requests;
using mad.Common;
using mad.Http;

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

        cmd.AddOption(name);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);

        cmd.SetHandler(async (string url, string? token, string name) =>
        {
            token ??= AuthUtils.TryLoadToken();
            if (string.IsNullOrWhiteSpace(token))
            {
                Console.Error.WriteLine("No token. Use --admin-token or run `mad session login`.");
                return;
            }

            var client = new MadApiClient(url, token);
            var result = await client.CreatePermission(new CreatePermissionRequest { Name = name });
            Console.WriteLine(result);
        }, adminUrl, adminToken, name);

        return cmd;
    }

    private static Command ListPermissionsCommand()
    {
        var cmd = new Command("list", "List all permissions");

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
            var perms = await client.ListPermissions();

            if (perms.Count == 0)
            {
                Console.WriteLine("(no permissions)");
                return;
            }

            Console.WriteLine($"{"ID",-36}  {"Name",-20}");
            Console.WriteLine(new string('-', 100));
            foreach (var p in perms)
                Console.WriteLine($"{p.Id,-36}  {p.Name,-20}");

        }, adminUrl, adminToken);

        return cmd;
    }

    private static Command DeletePermissionCommand()
    {
        var cmd = new Command("delete", "Delete (deactivate) a permission");
        var id = new Option<string>("--id") { IsRequired = true };
        
        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;

        cmd.AddOption(id);
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
            var ok = await client.DeletePermission(id);
            Console.WriteLine(ok ? $"Deleted permission '{id}'" : $"Failed to delete '{id}'");
        }, adminUrl, adminToken, id);

        return cmd;
    }

    private static Command AssignPermissionCommand()
    {
        var cmd = new Command("assign", "Assign permissions to a role");

        var roleId = new Option<string>("--role-id") { IsRequired = true };
        var permIds = new Option<List<string>>("--permission-id") { IsRequired = true, AllowMultipleArgumentsPerToken = true };

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;

        cmd.AddOption(roleId);
        cmd.AddOption(permIds);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);

        cmd.SetHandler(async (string url, string? token, string rid, List<string> pids) =>
        {
            token ??= AuthUtils.TryLoadToken();
            if (string.IsNullOrWhiteSpace(token))
            {
                Console.Error.WriteLine("No token.");
                return;
            }

            var client = new MadApiClient(url, token);
            var ok = await client.AssignPermissionsToRole(rid, pids);
            Console.WriteLine(ok ? "Permissions assigned." : "Failed to assign.");
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
            token ??= AuthUtils.TryLoadToken();
            if (string.IsNullOrWhiteSpace(token))
            {
                Console.Error.WriteLine("No token.");
                return;
            }

            var client = new MadApiClient(url, token);
            var ok = await client.RemovePermissionFromRole(rid, pid);
            Console.WriteLine(ok ? "Permission removed." : "Failed to remove.");
        }, adminUrl, adminToken, roleId, permId);

        return cmd;
    }

    private static Command ListPermissionsForRoleCommand()
    {
        var cmd = new Command("list-for-role", "List permissions for a role");
        var roleId = new Option<string>("--role-id") { IsRequired = true };
        
        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;

        cmd.AddOption(roleId);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);

        cmd.SetHandler(async (string url, string? token, string rid) =>
        {
            token ??= AuthUtils.TryLoadToken();
            if (string.IsNullOrWhiteSpace(token))
            {
                Console.Error.WriteLine("No token.");
                return;
            }

            var client = new MadApiClient(url, token);
            var perms = await client.ListPermissionsForRole(rid);
            foreach (var p in perms)
                Console.WriteLine(p);
        }, adminUrl, adminToken, roleId);

        return cmd;
    }

    private static Command ListPermissionsForUserCommand()
    {
        var cmd = new Command("list-for-user", "List effective permissions for a user");
        var userId = new Option<string>("--user-id") { IsRequired = true };
        
        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;

        cmd.AddOption(userId);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);

        cmd.SetHandler(async (string url, string? token, string uid) =>
        {
            token ??= AuthUtils.TryLoadToken();
            if (string.IsNullOrWhiteSpace(token))
            {
                Console.Error.WriteLine("No token.");
                return;
            }

            var client = new MadApiClient(url, token);
            var perms = await client.ListPermissionsForUser(uid);
            foreach (var p in perms)
                Console.WriteLine(p);
        }, adminUrl, adminToken, userId);

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
            token ??= AuthUtils.TryLoadToken();
            if (string.IsNullOrWhiteSpace(token))
            {
                Console.Error.WriteLine("No token.");
                return;
            }

            var client = new MadApiClient(url, token);
            var access = await client.CheckAccess(uid, pid);
            Console.WriteLine(access ? "User has permission." : "User does NOT have permission.");
        }, adminUrl, adminToken, userId, permId);

        return cmd;
    }
}