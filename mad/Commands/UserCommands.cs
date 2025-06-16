using System.CommandLine;

using madTypes.Api.Requests;
using mad.Http;
using mad.Common;

namespace mad.Commands;

internal static class UserCommands
{
    public static Command Build()
    {
        var cmd = new Command("user", "Manage users");
        cmd.AddCommand(CreateUserCommand());
        cmd.AddCommand(ListUsersCommand());
        cmd.AddCommand(DeleteUserCommand());
        cmd.AddCommand(ActivateUserCommand());
        return cmd;
    }

    private static Command CreateUserCommand()
    {
        var cmd = new Command("create", "Create a new user");

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var username = new Option<string>("--username") { IsRequired = true };
        var email = new Option<string>("--user-email") { IsRequired = true };
        var password = new Option<string>("--user-password") { IsRequired = true };
        var clientIdent = new Option<string>("--client-id") { IsRequired = true };
                
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(username);
        cmd.AddOption(email);
        cmd.AddOption(password);
        
        cmd.SetHandler(async (string url, string? tokenOverride, string u, string e, string p) =>
        {
            Console.WriteLine($"url = {url}, tokenOverride = {tokenOverride}, u = {u}, e = {e}, p = {p}");

            var token = string.IsNullOrWhiteSpace(tokenOverride)
                ? AuthUtils.TryLoadToken()
                : tokenOverride;

            if (string.IsNullOrWhiteSpace(token))
            {
                Console.Error.WriteLine("Error: no admin token provided. Use --admin-token or run `mad session login`.");
                return;
            }

            var client = new MadApiClient(url, token);

            var request = new CreateUserRequest
            {
                Username = u,
                Email = e,
                Password = p
            };

            try
            {
                var res = await client.CreateUser(request);

                if (res.IsSuccessStatusCode)
                {
                    Console.WriteLine($"Created user '{u}'");
                }
                else
                {
                    var body = await res.Content.ReadAsStringAsync();
                    Console.Error.WriteLine($"Failed to create user '{u}': {body}");
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Request failed: {ex.Message}");
            }

        }, adminUrl, adminToken, username, email, password);

        return cmd;
    }

    private static Command ListUsersCommand()
    {
        var cmd = new Command("list", "List all users");

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;

        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);

        cmd.SetHandler(async (string url, string? tokenOverride) =>
        {
            var token = string.IsNullOrWhiteSpace(tokenOverride)
                ? AuthUtils.TryLoadToken()
                : tokenOverride;

            if (string.IsNullOrWhiteSpace(token))
            {
                Console.Error.WriteLine("No admin token provided. Use --admin-token or run `mad session login`.");
                return;
            }

            var client = new MadApiClient(url, token);
            var users = await client.ListUsers();

            if (users == null)
            {
                Console.Error.WriteLine("Failed to retrieve user list.");
                return;
            }

            Console.WriteLine($"{"Id",-36}  {"Username",-20}  {"Email",-30}  Status");
            Console.WriteLine(new string('-', 100));
            foreach (var user in users)
            {
                Console.WriteLine($"{user.Id,-36} {user.Username,-20} {user.Email,-30} {(user.IsActive ? "ACTIVE" : "INACTIVE")}");
            }
        }, adminUrl, adminToken);

        return cmd;
    }

    private static Command DeleteUserCommand()
    {
        var cmd = new Command("delete", "Delete (deactivate) a user");

        var userId = new Option<string>("--id") { IsRequired = true };
        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;

        cmd.AddOption(userId);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);

        cmd.SetHandler(async (string url, string? tokenOverride, string id) =>
        {
            var token = string.IsNullOrWhiteSpace(tokenOverride)
                ? AuthUtils.TryLoadToken()
                : tokenOverride;

            if (string.IsNullOrWhiteSpace(token))
            {
                Console.Error.WriteLine("No admin token provided. Use --admin-token or run `mad session login`.");
                return;
            }

            var client = new MadApiClient(url, token);
            var success = await client.DeleteUser(id);

            if (success)
                Console.WriteLine($"Deactivated user '{id}'");
            else
                Console.Error.WriteLine($"Failed to deactivate user '{id}'");
        }, adminUrl, adminToken, userId);

        return cmd;
    }

    private static Command ActivateUserCommand()
    {
        var cmd = new Command("activate", "Mark a deactivated user as active again");

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var userId = new Option<string>("--id") { IsRequired = true };

        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(userId);

        cmd.SetHandler(async (string adminUrl, string? token, string id) =>
        {
            token ??= AuthUtils.TryLoadToken();
            if (string.IsNullOrWhiteSpace(token))
            {
                Console.Error.WriteLine("No token. Use --admin-token or run `mad session login`.");
                return;
            }

            var client = new MadApiClient(adminUrl, token);
            var ok = await client.ActivateUser(id);
            Console.WriteLine(ok ? $"User '{id}' reactivated." : $"Failed to reactivate user '{id}'.");
        }, adminUrl, adminToken, userId);

        return cmd;
    }

}
