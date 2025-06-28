using mad.Common;
using mad.Http;
using madTypes.Api.Responses;
using System.CommandLine;
using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;

namespace mad.Commands;

internal static class SessionCommands
{
    public static Command Build()
    {
        var cmd = new Command("session", "Manage login session");
        cmd.AddCommand(LoginCommand());
        cmd.AddCommand(LogoutCommand());
        cmd.AddCommand(StatusCommand());
        return cmd;
    }

    private static Command LoginCommand()
    {
        var adminUrl = SharedOptions.AdminUrl;
        var jsonOut = SharedOptions.OutputJson;

        var cmd = new Command("login", "Authenticate and store admin token");
        cmd.AddOption(adminUrl);
        cmd.AddOption(jsonOut);

        cmd.SetHandler(async (string url, bool json) =>
        {
            try
            {
                Console.Write("Username: ");
                var username = Console.ReadLine() ?? string.Empty;

                Console.Write("Password: ");
                var password = ConsoleUtils.ReadHiddenInput();

                var client = new MadApiClient(url);
                var success = await client.Authenticate(username, password, "admin");

                if (!success || string.IsNullOrWhiteSpace(client.Token))
                {
                    if (json)
                    {
                        var err = new ErrorResponse(false, "Login failed. Check your credentials.");
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    }
                    else
                    {
                        Console.WriteLine("Login failed. Check your credentials.");
                    }
                    return;
                }

                AuthUtils.SaveToken(client.Token);
                AuthUtils.SaveAdminUrl(url);

                var handler = new JwtSecurityTokenHandler();
                var jwt = handler.ReadJwtToken(client.Token);
                var sub = jwt.Claims.FirstOrDefault(c => c.Type == "sub")?.Value ?? "unknown";

                if (json)
                {
                    var resp = new LoginResponse
                    {
                        Success = true,
                        Subject = sub,
                        Message = "Login successful"
                    };
                    Console.WriteLine(JsonSerializer.Serialize(resp, MadJsonContext.Default.LoginResponse));
                }
                else
                {
                    Console.WriteLine($"Logged in as {sub}. Run `mad session logout` when finished.");
                }
            }
            catch (Exception ex)
            {
                if (json)
                {
                    var err = new ErrorResponse(false, "Login failed due to an unexpected error.");
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                }
                else
                {
                    Console.Error.WriteLine("Login failed due to an unexpected error.");
                    Console.Error.WriteLine(ex.Message);
                }
            }
        }, adminUrl, jsonOut);

        return cmd;
    }

    private static Command LogoutCommand()
    {
        var jsonOut = SharedOptions.OutputJson;
        var cmd = new Command("logout", "Clear cached admin token");
        cmd.AddOption(jsonOut);

        cmd.SetHandler((bool json) =>
        {
            try
            {
                var ok = AuthUtils.DeleteToken();

                if (json)
                {
                    if (ok)
                    {
                        var msg = new MessageResponse(true, "Logged out. Token cache cleared.");
                        Console.WriteLine(JsonSerializer.Serialize(msg, MadJsonContext.Default.MessageResponse));
                    }
                    else
                    {
                        var err = new ErrorResponse(false, "No token found or unable to delete.");
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    }
                }
                else
                {
                    Console.WriteLine(ok
                        ? "Logged out. Token cache cleared."
                        : "No token found or unable to delete.");
                }
            }
            catch (Exception ex)
            {
                if (json)
                {
                    var err = new ErrorResponse(false, "Logout failed due to an unexpected error.");
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                }
                else
                {
                    Console.Error.WriteLine("Logout failed due to an unexpected error.");
                    Console.Error.WriteLine(ex.Message);
                }
            }
        }, jsonOut);

        return cmd;
    }

    private static Command StatusCommand()
    {
        var cmd = new Command("status", "Show cached session info (if any)");

        var jsonOut = SharedOptions.OutputJson;
        cmd.AddOption(jsonOut);

        cmd.SetHandler((bool json) =>
        {
            try
            {
                var token = AuthUtils.TryLoadToken();
                if (string.IsNullOrWhiteSpace(token))
                {
                    if (json)
                    {
                        var err = new ErrorResponse(false, "Not logged in.");
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    }
                    else
                    {
                        Console.WriteLine("Not logged in.");
                    }
                    return;
                }

                var handler = new JwtSecurityTokenHandler();
                var jwt = handler.ReadJwtToken(token);

                var sub = jwt.Claims.FirstOrDefault(c => c.Type == "sub")?.Value ?? "unknown";
                var exp = jwt.Claims.FirstOrDefault(c => c.Type == "exp")?.Value;
                var role = jwt.Claims.FirstOrDefault(c => c.Type == "role")?.Value ?? "(none)";
                var tokenUse = jwt.Claims.FirstOrDefault(c => c.Type == "token_use")?.Value ?? "unknown";

                var expTime = exp is not null
                    ? DateTimeOffset.FromUnixTimeSeconds(long.Parse(exp)).UtcDateTime.ToString("u")
                    : "(unknown)";

                if (json)
                {
                    var resp = new SessionStatusResponse
                    {
                        Subject = sub,
                        Role = role,
                        ExpiresAt = expTime,
                        TokenUse = tokenUse
                    };

                    Console.WriteLine(JsonSerializer.Serialize(resp, MadJsonContext.Default.SessionStatusResponse));
                }
                else
                {
                    Console.WriteLine($"Logged in as: {sub}");
                    Console.WriteLine($"Role:         {role}");
                    Console.WriteLine($"Expires at:   {expTime}");
                    Console.WriteLine($"Token use:    {tokenUse}");
                }
            }
            catch (Exception ex)
            {
                if (json)
                {
                    var err = new ErrorResponse(false, "Token is invalid or corrupted.");
                    Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                }
                else
                {
                    Console.WriteLine("Token is invalid or corrupted.");
                    Console.Error.WriteLine(ex.Message);
                }
            }
        }, jsonOut);

        return cmd;
    }
}
