using System.CommandLine;
using System.IdentityModel.Tokens.Jwt;

using mad.Common;
using mad.Http;

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

        var cmd = new Command("login", "Authenticate and store admin token");
        cmd.AddOption(adminUrl);

        cmd.SetHandler(async (string url) =>
        {
            Console.Write("Username: ");
            var username = Console.ReadLine() ?? string.Empty;

            Console.Write("Password: ");
            var password = ConsoleUtils.ReadHiddenInput();

            var client = new MadApiClient(url);
            var success = await client.Authenticate(username, password);

            if (!success)
            {
                Console.WriteLine("Login failed. Check your credentials.");
                return;
            }

            if (!string.IsNullOrWhiteSpace(client.Token))
            {
                AuthUtils.SaveToken(client.Token);
                var handler = new JwtSecurityTokenHandler();
                var jwt = handler.ReadJwtToken(client.Token);
                var sub = jwt.Claims.FirstOrDefault(c => c.Type == "sub")?.Value ?? "unknown";

                Console.WriteLine($"Logged in as {sub}. Run `mad session logout` when finished.");
            }
        }, adminUrl);

        return cmd;
    }

    private static Command LogoutCommand()
    {
        var cmd = new Command("logout", "Clear cached admin token");
        cmd.SetHandler(() =>
        {
            if (AuthUtils.DeleteToken())
                Console.WriteLine("Logged out. Token cache cleared.");
            else
                Console.WriteLine("No token found or unable to delete.");
        });
        return cmd;
    }

    private static Command StatusCommand()
    {
        var cmd = new Command("status", "Show cached session info (if any)");
        cmd.SetHandler(() =>
        {
            var token = AuthUtils.TryLoadToken();
            if (string.IsNullOrWhiteSpace(token))
            {
                Console.WriteLine("Not logged in.");
                return;
            }

            try
            {
                var handler = new JwtSecurityTokenHandler();
                var jwt = handler.ReadJwtToken(token);

                var sub = jwt.Claims.FirstOrDefault(c => c.Type == "sub")?.Value ?? "unknown";
                var exp = jwt.Claims.FirstOrDefault(c => c.Type == "exp")?.Value;
                var role = jwt.Claims.FirstOrDefault(c => c.Type == "role")?.Value ?? "(none)";
                var tokenUse = jwt.Claims.FirstOrDefault(c => c.Type == "token_use")?.Value ?? "unknown";

                var expTime = exp is not null
                    ? DateTimeOffset.FromUnixTimeSeconds(long.Parse(exp)).UtcDateTime.ToString("u")
                    : "(unknown)";

                Console.WriteLine($"Logged in as: {sub}");
                Console.WriteLine($"Role:         {role}");
                Console.WriteLine($"Expires at:   {expTime}");
                Console.WriteLine($"Token use:    {tokenUse}");
            }
            catch
            {
                Console.WriteLine("Token is invalid or corrupted.");
            }
        });

        return cmd;
    }
}
