﻿using mad.Common;
using mad.Http;
using madTypes.Api.Requests;
using madTypes.Api.Responses;
using System.CommandLine;
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

namespace mad.Commands;

internal static class UserCommands
{
    public static Command Build()
    {
        var cmd = new Command("user", "Manage users");
        cmd.AddCommand(CreateUserCommand());
        cmd.AddCommand(TotpQr());
        cmd.AddCommand(TotpVerifyCommand());
        cmd.AddCommand(DisableTotpCommand());
        cmd.AddCommand(UpdateUserCommand());
        cmd.AddCommand(MarkEmailVerifiedCommand());
        cmd.AddCommand(ResetPasswordCommand());
        cmd.AddCommand(ListUsersCommand());
        cmd.AddCommand(GetUserByIdCommand());

        cmd.AddCommand(DeactivateUserCommand());
        cmd.AddCommand(ActivateUserCommand());
        cmd.AddCommand(DeleteUserCommand());

        cmd.AddCommand(SetUserLockoutCommand());
        cmd.AddCommand(ClearUserLockoutCommand());

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

    private static Command TotpQr()
    {
        var cmd = new Command("totp-qr", "Generate TOTP QR for a user");

        var userId = new Option<string>("--id") { IsRequired = true };
        var clientId = new Option<string>("--client-id") { IsRequired = true };
        var pathOpt = new Option<string>("--output-path", () => ".") { Description = "Where to save the QR SVG" };
        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(userId);
        cmd.AddOption(clientId);
        cmd.AddOption(pathOpt);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string url, string? token, string uid, string cid, string path, bool json) =>
        {
            token ??= AuthUtils.TryLoadToken();
            if (string.IsNullOrWhiteSpace(token))
            {
                Console.Error.WriteLine("No token.");
                return;
            }

            var client = new MadApiClient(url, token);
            var result = await client.GenerateTotpQrCode(new TotpQrRequest
            {
                UserId = uid,
                ClientId = cid,
                QrOutputPath = path
            });

            if (json)
            {
#pragma warning disable CS8619 // Nullability of reference types doesn't match target type
                var typeInfo = (JsonTypeInfo<TotpQrResponse?>)MadJsonContext.Default.TotpQrResponse;
                Console.WriteLine(JsonSerializer.Serialize(result, typeInfo));
            }
            else if (result?.Success == true)
            {
                Console.WriteLine($"TOTP QR generated: {result.Filename}");
            }
            else
            {
                Console.Error.WriteLine("Failed to generate TOTP QR.");
            }

        }, adminUrl, adminToken, userId, clientId, pathOpt, jsonOut);

        return cmd;
    }

    private static Command TotpVerifyCommand()
    {
        var cmd = new Command("totp-verify", "Verify a TOTP code for a user");

        var userId = new Option<string>("--user-id") { IsRequired = true };
        var clientId = new Option<string>("--client-id") { IsRequired = true };
        var code = new Option<string>("--code") { IsRequired = true };
        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(userId);
        cmd.AddOption(clientId);
        cmd.AddOption(code);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string url, string? token, string uid, string cid, string code, bool json) =>
        {
            token ??= AuthUtils.TryLoadToken();
            if (string.IsNullOrWhiteSpace(token))
            {
                Console.Error.WriteLine("No token.");
                return;
            }

            var client = new MadApiClient(url, token);
            var result = await client.VerifyTotpCode(new VerifyTotpRequest
            {
                UserId = uid,
                ClientId = cid,
                Code = code
            });

            if (result == null)
            {
                Console.Error.WriteLine("Failed to verify TOTP.");
                return;
            }

            if (json)
            {
                Console.WriteLine(JsonSerializer.Serialize(result, MadJsonContext.Default.MessageResponse));
            }
            else
            {
                Console.WriteLine(result.Success ? "TOTP verified and enabled" : $"Failed: {result.Message}");
            }
        }, adminUrl, adminToken, userId, clientId, code, jsonOut);

        return cmd;
    }

    private static Command DisableTotpCommand()
    {
        var cmd = new Command("disable-totp", "Disable TOTP for a user");

        var userId = new Option<string>("--user-id") { IsRequired = true };
        var clientId = new Option<string>("--client-id") { IsRequired = true };
        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(userId);
        cmd.AddOption(clientId);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string url, string? token, string uid, string cid, bool json) =>
        {
            token ??= AuthUtils.TryLoadToken();
            if (string.IsNullOrWhiteSpace(token))
            {
                Console.Error.WriteLine("No token.");
                return;
            }

            var client = new MadApiClient(url, token);
            var result = await client.DisableTotpForUser(uid, cid);

            if (result is null)
            {
                Console.Error.WriteLine("Failed to disable TOTP.");
                return;
            }

            if (json)
                Console.WriteLine(JsonSerializer.Serialize(result, MadJsonContext.Default.MessageResponse));
            else
                Console.WriteLine(result.Message);

        }, adminUrl, adminToken, userId, clientId, jsonOut);

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

    private static Command MarkEmailVerifiedCommand()
    {
        var cmd = new Command("verify-email", "Mark a user's email as verified");

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
            token ??= AuthUtils.TryLoadToken();
            if (string.IsNullOrWhiteSpace(token))
            {
                Console.WriteLine(JsonSerializer.Serialize(
                    new ErrorResponse(false, "No token. Use --admin-token or `mad session login`."),
                    MadJsonContext.Default.ErrorResponse));
                return;
            }

            var client = new MadApiClient(url, token);
            var response = await client.MarkEmailVerified(id);

            if (response is null)
            {
                Console.WriteLine(JsonSerializer.Serialize(
                    new ErrorResponse(false, "Failed to mark email as verified."),
                    MadJsonContext.Default.ErrorResponse));
                return;
            }

            if (json)
                Console.WriteLine(JsonSerializer.Serialize(response, MadJsonContext.Default.MessageResponse));
            else
                Console.WriteLine("Email marked as verified.");
        }, adminUrl, adminToken, id, jsonOut);

        return cmd;
    }

    /// <summary>
    /// Creates a command for resetting a user's password.
    /// </summary>
    /// <remarks>The command requires the user ID and the new password to be specified as options. Additional
    /// options include the admin URL, admin token, and a flag to output the result in JSON format. This command
    /// interacts with the API to reset the password and provides feedback on the operation's success or
    /// failure.</remarks>
    /// <returns>A <see cref="Command"/> instance configured to reset a user's password.</returns>
    private static Command ResetPasswordCommand()
    {
        var cmd = new Command("reset-password", "Reset a user's password");

        var id = new Option<string>("--id", "User ID") { IsRequired = true };
        var newPass = new Option<string>("--new-password", "New password") { IsRequired = true };
        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(id);
        cmd.AddOption(newPass);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string id, string newPass, string url, string? token, bool json) =>
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
                var result = await client.ResetUserPassword(id, newPass);

                if (result is null)
                {
                    var err = new ErrorResponse(false, "Password reset failed.");
                    if (json)
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    else
                        Console.Error.WriteLine(err.Message);
                    return;
                }

                if (json)
                    Console.WriteLine(JsonSerializer.Serialize(result, MadJsonContext.Default.MessageResponse));
                else
                    Console.WriteLine("Password was reset successfully.");

            }
            catch (Exception ex)
            {
                var err = new ErrorResponse(false, $"Exception during password reset: {ex.Message}");
                if (json)
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                else
                {
                    Console.Error.WriteLine("Error resetting password.");
                    Console.Error.WriteLine(ex.Message);
                }
            }
        }, id, newPass, adminUrl, adminToken, jsonOut);

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

    private static Command SetUserLockoutCommand()
    {
        var cmd = new Command("set-lockout", "Manually set a user lockout timestamp");

        var id = new Option<string>("--id") { IsRequired = true };
        var until = new Option<string>("--until", "ISO-8601 or 'permanent'") { IsRequired = true };

        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(id);
        cmd.AddOption(until);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string id, string until, string url, string? token, bool json) =>
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

                DateTime lockoutTime;
                if (until.Trim().ToLowerInvariant() == "permanent")
                {
                    lockoutTime = DateTime.MaxValue;
                }
                else if (!DateTime.TryParse(until, null, DateTimeStyles.AdjustToUniversal, out lockoutTime))
                {
                    var err = new ErrorResponse(false, $"Invalid time format for --until: '{until}'");
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    return;
                }

                var client = new MadApiClient(url, token);
                var result = await client.SetUserLockout(id, lockoutTime);

                if (json)
                    Console.WriteLine(JsonSerializer.Serialize(result, MadJsonContext.Default.MessageResponse));
                else
                    Console.WriteLine(result.Message);
            }
            catch (Exception ex)
            {
                var err = new ErrorResponse(false, $"Unexpected error: {ex.Message}");
                Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
            }
        }, id, until, adminUrl, adminToken, jsonOut);

        return cmd;
    }

    private static Command ClearUserLockoutCommand()
    {
        var cmd = new Command("clear-lockout", "Remove any lockout restrictions from a user");

        var id = new Option<string>("--id") { IsRequired = true };
        var adminUrl = SharedOptions.AdminUrl;
        var adminToken = SharedOptions.AdminToken;
        var jsonOut = SharedOptions.OutputJson;

        cmd.AddOption(id);
        cmd.AddOption(adminUrl);
        cmd.AddOption(adminToken);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string id, string url, string? token, bool json) =>
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
                var result = await client.ClearUserLockout(id);

                if (json)
                    Console.WriteLine(JsonSerializer.Serialize(result, MadJsonContext.Default.MessageResponse));
                else
                    Console.WriteLine(result.Message);
            }
            catch (Exception ex)
            {
                var err = new ErrorResponse(false, $"Unexpected error: {ex.Message}");
                Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
            }
        }, id, adminUrl, adminToken, jsonOut);

        return cmd;
    }

}
