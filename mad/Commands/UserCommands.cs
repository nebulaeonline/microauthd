using mad.Common;
using mad.Http;
using madTypes.Api.Requests;
using System.CommandLine;
using System.Text.Json;

namespace mad.Commands;

internal static class UserCommands
{
    public static Command Build()
    {
        var cmd = new Command("user", "Manage users");
        cmd.AddCommand(CreateUserCommand());
        cmd.AddCommand(ListUsersCommand());
        cmd.AddCommand(DeactivateUserCommand());
        cmd.AddCommand(ActivateUserCommand());
        return cmd;
    }

    private static Command CreateUserCommand()
    {
        var cmd = new Command("create", "Create a new user");

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;
        var username = new Option<string>("--username") { IsRequired = true };
        var email = new Option<string>("--user-email") { IsRequired = true };
        var password = new Option<string>("--user-password") { IsRequired = true };
                
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(username);
        cmd.AddOption(email);
        cmd.AddOption(password);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string url, string? tokenOverride, string u, string e, string p, bool jsonOut) =>
        {
            try
            {
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

                var res = await client.CreateUser(request);

                if (res is null)
                {
                    Console.Error.WriteLine("Failed to create user.");
                    return;
                }

                if (jsonOut)
                {
                    Console.WriteLine(JsonSerializer.Serialize(res, MadJsonContext.Default.UserResponse));
                }
                else
                {
                    Console.WriteLine($"Created user {u} with Id: {res.Id}");
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error creating user '{u}': {ex.Message}");
            }
        }, adminUrl, adminToken, username, email, password, jsonOut);

        return cmd;
    }

    private static Command ListUsersCommand()
    {
        var cmd = new Command("list", "List all users");

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var json = SharedOptions.OutputJson;

        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(json);

        cmd.SetHandler(async (string url, string? tokenOverride, bool asJson) =>
        {
            try
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

                if (asJson)
                {
                    Console.WriteLine(JsonSerializer.Serialize(users, MadJsonContext.Default.ListUserResponse));
                }
                else
                {
                    Console.WriteLine($"{"Id",-36}  {"Username",-20}  {"Email",-30}  Status");
                    Console.WriteLine(new string('-', 100));
                    foreach (var user in users)
                    {
                        Console.WriteLine($"{user.Id,-36} {user.Username,-20} {user.Email,-30} {(user.IsActive ? "ACTIVE" : "INACTIVE")}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error listing users: {ex.Message}");
            }
        }, adminUrl, adminToken, json);

        return cmd;
    }

    private static Command DeactivateUserCommand()
    {
        var cmd = new Command("deactivate", "Deactivate a user");

        var userId = new Option<string>("--id") { IsRequired = true };
        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;

        cmd.AddOption(userId);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);

        cmd.SetHandler(async (string url, string? tokenOverride, string id) =>
        {
            try
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
                var success = await client.DeactivateUser(id);

                if (success)
                    Console.WriteLine($"Deactivated user {id}");
                else
                    Console.Error.WriteLine($"Failed to deactivate user {id}");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error deactivating user: {ex.Message}");
            }
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
            try
            {
                token ??= AuthUtils.TryLoadToken();
                if (string.IsNullOrWhiteSpace(token))
                {
                    Console.Error.WriteLine("No token. Use --admin-token or run `mad session login`.");
                    return;
                }

                var client = new MadApiClient(adminUrl, token);
                var ok = await client.ActivateUser(id);
                Console.WriteLine(ok ? $"User {id} reactivated." : $"Failed to reactivate user {id}.");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error activating user: {ex.Message}");
            }
        }, adminUrl, adminToken, userId);

        return cmd;
    }

}
