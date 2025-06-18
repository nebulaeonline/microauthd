using mad.Common;
using mad.Http;
using madTypes.Api.Requests;
using madTypes.Api.Responses;
using System.CommandLine;
using System.Text.Json;

namespace mad.Commands;

internal static class UserCommands
{
    public static Command Build()
    {
        var cmd = new Command("user", "Manage users");
        cmd.AddCommand(CreateUserCommand());
        cmd.AddCommand(UpdateUserCommand());
        cmd.AddCommand(ListUsersCommand());
        cmd.AddCommand(GetUserByIdCommand());
        cmd.AddCommand(DeactivateUserCommand());
        cmd.AddCommand(ActivateUserCommand());
        cmd.AddCommand(DeleteUserCommand());
        
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
                    if (jsonOut)
                    {
                        var err = new ErrorResponse(false, "No admin token provided. Use --admin-token or run `mad session login`.");
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    }
                    else
                    {
                        Console.Error.WriteLine("Error: no admin token provided. Use --admin-token or run `mad session login`.");
                    }
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
                    if (jsonOut)
                    {
                        var err = new ErrorResponse(false, "Failed to create user.");
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    }
                    else
                    {
                        Console.Error.WriteLine("Failed to create user.");
                    }
                    return;
                }

                if (jsonOut)
                {
                    Console.WriteLine(JsonSerializer.Serialize(res, MadJsonContext.Default.UserObject));
                }
                else
                {
                    Console.WriteLine($"Created user {u} with Id: {res.Id}");
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
                    Console.Error.WriteLine($"Error creating user '{u}': {ex.Message}");
                }
            }
        }, adminUrl, adminToken, username, email, password, jsonOut);

        return cmd;
    }

    private static Command GetUserByIdCommand()
    {
        var cmd = new Command("get", "Fetch a single user by ID");

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
                    var err = new ErrorResponse(false, "No token. Use --admin-token or `mad session login`.");
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    return;
                }

                var client = new MadApiClient(url, token);
                var user = await client.GetUserById(id);

                if (user is null)
                {
                    var err = new ErrorResponse(false, $"User with id {id} not found.");
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    return;
                }

                if (json)
                {
                    Console.WriteLine(JsonSerializer.Serialize(user, MadJsonContext.Default.UserObject));
                }
                else
                {
                    Console.WriteLine($"Id:        {user.Id}");
                    Console.WriteLine($"Username:  {user.Username}");
                    Console.WriteLine($"Email:     {user.Email}");
                    Console.WriteLine($"Active:    {user.IsActive}");
                    Console.WriteLine($"Created:   {user.CreatedAt}");
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

    private static Command UpdateUserCommand()
    {
        var cmd = new Command("update", "Update an existing user");

        var id = new Option<string>("--id") { IsRequired = true };
        var username = new Option<string?>("--username", "New username");
        var email = new Option<string?>("--email", "New email");
        var active = new Option<bool?>("--is-active", "Set account active (true/false)");

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(id);
        cmd.AddOption(username);
        cmd.AddOption(email);
        cmd.AddOption(active);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (
            string url,
            string? tokenOverride,
            string id,
            string? newUsername,
            string? newEmail,
            bool? isActive,
            bool json
        ) =>
        {
            try
            {
                var token = string.IsNullOrWhiteSpace(tokenOverride)
                    ? AuthUtils.TryLoadToken()
                    : tokenOverride;

                if (string.IsNullOrWhiteSpace(token))
                {
                    var err = new ErrorResponse(false, "No admin token provided.");
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    return;
                }

                if (newUsername is null && newEmail is null && isActive is null)
                {
                    var err = new ErrorResponse(false, "You must provide at least one field to update.");
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    return;
                }

                var client = new MadApiClient(url, token);
                var existing = await client.GetUserById(id);

                if (existing is null)
                {
                    var err = new ErrorResponse(false, $"User '{id}' not found.");
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    return;
                }

                // Overlay changes
                if (newUsername != null) existing.Username = newUsername;
                if (newEmail != null) existing.Email = newEmail;
                if (isActive.HasValue) existing.IsActive = isActive.Value;

                var updated = await client.UpdateUser(id, existing);

                if (updated is null)
                {
                    var err = new ErrorResponse(false, "Update failed.");
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    return;
                }

                if (json)
                {
                    Console.WriteLine(JsonSerializer.Serialize(updated, MadJsonContext.Default.UserObject));
                }
                else
                {
                    Console.WriteLine($"User updated: {updated.Username} ({updated.Email}) [{(updated.IsActive ? "ACTIVE" : "INACTIVE")}]");
                }
            }
            catch (Exception ex)
            {
                var err = new ErrorResponse(false, $"Unexpected error: {ex.Message}");
                Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
            }
        }, adminUrl, adminToken, id, username, email, active, jsonOut);

        return cmd;
    }

    private static Command ListUsersCommand()
    {
        var cmd = new Command("list", "List all users");

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string url, string? tokenOverride, bool json) =>
        {
            try
            {
                var token = string.IsNullOrWhiteSpace(tokenOverride)
                    ? AuthUtils.TryLoadToken()
                    : tokenOverride;

                if (string.IsNullOrWhiteSpace(token))
                {
                    if (json)
                    {
                        var err = new ErrorResponse(false, "No admin token provided. Use --admin-token or run `mad session login`.");
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    }
                    else
                    {
                        Console.Error.WriteLine("No admin token provided. Use --admin-token or run `mad session login`.");
                    }
                    return;
                }

                var client = new MadApiClient(url, token);
                var users = await client.ListUsers();

                if (users == null)
                {
                    if (json)
                    {
                        var err = new ErrorResponse(false, "Failed to retrieve user list.");
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    }
                    else
                    {
                        Console.Error.WriteLine("Failed to retrieve user list.");
                    }
                    return;
                }

                if (json)
                {
                    Console.WriteLine(JsonSerializer.Serialize(users, MadJsonContext.Default.ListUserObject));
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
                if (json)
                {
                    var err = new ErrorResponse(false, $"Exception: {ex.Message}");
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                }
                else
                {
                    Console.Error.WriteLine($"Error listing users: {ex.Message}");
                }
            }
        }, adminUrl, adminToken, jsonOut);

        return cmd;
    }

    private static Command DeactivateUserCommand()
    {
        var cmd = new Command("deactivate", "Deactivate a user");

        var userId = new Option<string>("--id") { IsRequired = true };
        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(userId);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string url, string? tokenOverride, string id, bool json) =>
        {
            try
            {
                var token = string.IsNullOrWhiteSpace(tokenOverride)
                    ? AuthUtils.TryLoadToken()
                    : tokenOverride;

                if (string.IsNullOrWhiteSpace(token))
                {
                    if (json)
                    {
                        var err = new ErrorResponse(false, "No admin token provided. Use --admin-token or run `mad session login`.");
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    }
                    else
                    {
                        Console.Error.WriteLine("No admin token provided. Use --admin-token or run `mad session login`.");
                    }
                    return;
                }

                var client = new MadApiClient(url, token);
                var success = await client.DeactivateUser(id);

                if (json)
                {
                    if (success)
                    {
                        var msg = new MessageResponse(true, $"Deactivated user {id}");
                        Console.WriteLine(JsonSerializer.Serialize(msg, MadJsonContext.Default.MessageResponse));
                    }
                    else
                    {
                        var err = new ErrorResponse(false, $"Failed to deactivate user {id}");
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    }
                }
                else
                {
                    if (success)
                        Console.WriteLine($"Deactivated user {id}");
                    else
                        Console.Error.WriteLine($"Failed to deactivate user {id}");
                }
            }
            catch (Exception ex)
            {
                if (json)
                {
                    var err = new ErrorResponse(false, $"Exception while deactivating user: {ex.Message}");
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                }
                else
                {
                    Console.Error.WriteLine($"Error deactivating user: {ex.Message}");
                }
            }
        }, adminUrl, adminToken, userId, jsonOut);

        return cmd;
    }

    private static Command ActivateUserCommand()
    {
        var cmd = new Command("activate", "Mark a deactivated user as active again");

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var userId = new Option<string>("--id") { IsRequired = true };
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(userId);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string adminUrl, string? token, string id, bool json) =>
        {
            try
            {
                token ??= AuthUtils.TryLoadToken();
                if (string.IsNullOrWhiteSpace(token))
                {
                    if (json)
                    {
                        var err = new ErrorResponse(false, "No token. Use --admin-token or run `mad session login`.");
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    }
                    else
                    {
                        Console.Error.WriteLine("No token. Use --admin-token or run `mad session login`.");
                    }
                    return;
                }

                var client = new MadApiClient(adminUrl, token);
                var ok = await client.ActivateUser(id);

                if (json)
                {
                    if (ok)
                    {
                        var msg = new MessageResponse(true, $"User {id} reactivated.");
                        Console.WriteLine(JsonSerializer.Serialize(msg, MadJsonContext.Default.MessageResponse));
                    }
                    else
                    {
                        var err = new ErrorResponse(false, $"Failed to reactivate user {id}.");
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    }
                }
                else
                {
                    Console.WriteLine(ok ? $"User {id} reactivated." : $"Failed to reactivate user {id}.");
                }
            }
            catch (Exception ex)
            {
                if (json)
                {
                    var err = new ErrorResponse(false, $"Error activating user: {ex.Message}");
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                }
                else
                {
                    Console.Error.WriteLine($"Error activating user: {ex.Message}");
                }
            }
        }, adminUrl, adminToken, userId, jsonOut);

        return cmd;
    }

    private static Command DeleteUserCommand()
    {
        var cmd = new Command("delete", "Permanently delete a user");

        var userId = new Option<string>("--id") { IsRequired = true };
        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(userId);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string url, string? tokenOverride, string id, bool json) =>
        {
            try
            {
                var token = string.IsNullOrWhiteSpace(tokenOverride)
                    ? AuthUtils.TryLoadToken()
                    : tokenOverride;

                if (string.IsNullOrWhiteSpace(token))
                {
                    if (json)
                    {
                        var err = new ErrorResponse(false, "No admin token provided. Use --admin-token or run `mad session login`.");
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    }
                    else
                    {
                        Console.Error.WriteLine("No admin token provided. Use --admin-token or run `mad session login`.");
                    }
                    return;
                }

                var client = new MadApiClient(url, token);
                var success = await client.DeleteUser(id);

                if (json)
                {
                    if (success)
                    {
                        var msg = new MessageResponse(true, $"Deleted user {id}");
                        Console.WriteLine(JsonSerializer.Serialize(msg, MadJsonContext.Default.MessageResponse));
                    }
                    else
                    {
                        var err = new ErrorResponse(false, $"Failed to delete user {id}");
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    }
                }
                else
                {
                    if (success)
                        Console.WriteLine($"Deleted user {id}");
                    else
                        Console.Error.WriteLine($"Failed to delete user {id}");
                }
            }
            catch (Exception ex)
            {
                if (json)
                {
                    var err = new ErrorResponse(false, $"Exception while deleting user: {ex.Message}");
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                }
                else
                {
                    Console.Error.WriteLine($"Error deleting user: {ex.Message}");
                }
            }
        }, adminUrl, adminToken, userId, jsonOut);

        return cmd;
    }
}
