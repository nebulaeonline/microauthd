using mad.Common;
using mad.Http;
using madTypes.Api.Responses;
using System;
using System.Collections.Generic;
using System.CommandLine;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace mad.Commands
{
    internal class RefreshTokenCommands
    {
        public static Command Build()
        {
            var cmd = new Command("refreshtoken", "Manage user refresh tokens");

            cmd.AddCommand(ListCommand());
            cmd.AddCommand(ListByUserCommand());
            cmd.AddCommand(GetByIdCommand());
            cmd.AddCommand(PurgeRefreshCommand());

            return cmd;
        }

        private static Command ListCommand()
        {
            var cmd = new Command("list", "List all refresh tokens");
            var adminUrl = SharedOptions.AdminUrl;
            var adminToken = SharedOptions.AdminToken;
            var jsonOut = SharedOptions.OutputJson;

            cmd.AddOption(adminUrl);
            cmd.AddOption(adminToken);
            cmd.AddOption(jsonOut);

            cmd.SetHandler(async (string url, string? token, bool json) =>
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
                    var tokens = await client.ListRefreshTokens();

                    if (tokens is null || tokens.Count == 0)
                    {
                        Console.WriteLine(json ? "[]" : "(no refresh tokens)");
                        return;
                    }

                    if (json)
                    {
                        Console.WriteLine(JsonSerializer.Serialize(tokens, MadJsonContext.Default.ListRefreshTokenResponse));
                    }
                    else
                    {
                        Console.WriteLine($"{"Id",-36}  {"User Id",-36}  Revoked  Expires At");
                        Console.WriteLine(new string('-', 100));
                        foreach (var rt in tokens)
                            Console.WriteLine($"{rt.Id,-36}  {rt.UserId,-36}  {rt.IsRevoked,-7}  {rt.ExpiresAt:u}");
                    }
                }
                catch (Exception ex)
                {
                    var err = new ErrorResponse(false, $"Error retrieving refresh tokens: {ex.Message}");
                    if (json)
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    else
                    {
                        Console.Error.WriteLine(err.Message);
                    }
                }
            }, adminUrl, adminToken, jsonOut);

            return cmd;
        }

        private static Command ListByUserCommand()
        {
            var cmd = new Command("list-by-user", "List refresh tokens for a specific user");

            var userId = new Option<string>("--user-id") { IsRequired = true };
            var adminUrl = SharedOptions.AdminUrl;
            var adminToken = SharedOptions.AdminToken;
            var jsonOut = SharedOptions.OutputJson;

            cmd.AddOption(userId);
            cmd.AddOption(adminUrl);
            cmd.AddOption(adminToken);
            cmd.AddOption(jsonOut);

            cmd.SetHandler(async (string uid, string url, string? token, bool json) =>
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
                    var tokens = await client.ListRefreshTokensForUser(uid);

                    if (tokens is null || tokens.Count == 0)
                    {
                        Console.WriteLine(json ? "[]" : "(no refresh tokens)");
                        return;
                    }

                    if (json)
                    {
                        Console.WriteLine(JsonSerializer.Serialize(tokens, MadJsonContext.Default.ListRefreshTokenResponse));
                    }
                    else
                    {
                        Console.WriteLine($"{"Id",-36}  Revoked  Expires At");
                        Console.WriteLine(new string('-', 80));
                        foreach (var rt in tokens)
                            Console.WriteLine($"{rt.Id,-36}  {rt.IsRevoked,-7}  {rt.ExpiresAt:u}");
                    }
                }
                catch (Exception ex)
                {
                    var err = new ErrorResponse(false, $"Error retrieving refresh tokens for user {uid}: {ex.Message}");
                    if (json)
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    else
                    {
                        Console.Error.WriteLine(err.Message);
                    }
                }
            }, userId, adminUrl, adminToken, jsonOut);

            return cmd;
        }

        private static Command GetByIdCommand()
        {
            var cmd = new Command("get", "Get a refresh token by ID");

            var id = new Option<string>("--id") { IsRequired = true };
            var adminUrl = SharedOptions.AdminUrl;
            var adminToken = SharedOptions.AdminToken;
            var jsonOut = SharedOptions.OutputJson;

            cmd.AddOption(id);
            cmd.AddOption(adminUrl);
            cmd.AddOption(adminToken);
            cmd.AddOption(jsonOut);

            cmd.SetHandler(async (string rid, string url, string? token, bool json) =>
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
                    var tokenInfo = await client.GetRefreshToken(rid);

                    if (tokenInfo is null)
                    {
                        if (json)
                        {
                            var err = new ErrorResponse(false, $"Refresh token {rid} not found.");
                            Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                        }
                        else
                        {
                            Console.WriteLine("Not found.");
                        }
                        return;
                    }

                    if (json)
                    {
                        Console.WriteLine(JsonSerializer.Serialize(tokenInfo, MadJsonContext.Default.RefreshTokenResponse));
                    }
                    else
                    {
                        Console.WriteLine($"Id:         {tokenInfo.Id}");
                        Console.WriteLine($"UserId:     {tokenInfo.UserId}");
                        Console.WriteLine($"IssuedAt:   {tokenInfo.IssuedAt:u}");
                        Console.WriteLine($"ExpiresAt:  {tokenInfo.ExpiresAt:u}");
                        Console.WriteLine($"Revoked:    {tokenInfo.IsRevoked}");
                        Console.WriteLine($"Client:     {tokenInfo.ClientIdentifier ?? "(none)"}");
                    }
                }
                catch (Exception ex)
                {
                    var err = new ErrorResponse(false, $"Error retrieving refresh token {rid}: {ex.Message}");
                    if (json)
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    else
                    {
                        Console.Error.WriteLine(err.Message);
                    }
                }
            }, id, adminUrl, adminToken, jsonOut);

            return cmd;
        }

        private static Command PurgeRefreshCommand()
        {
            var cmd = new Command("purge-refresh", "Purge refresh tokens by age or status");

            var seconds = new Option<int>("--older-than", "Purge refresh tokens older than N seconds") { IsRequired = true };
            var purgeExpired = new Option<bool>("--expired", "Include expired tokens") { IsRequired = false };
            var purgeRevoked = new Option<bool>("--revoked", "Include revoked tokens") { IsRequired = false };
            var adminUrl = SharedOptions.AdminUrl;
            var adminToken = SharedOptions.AdminToken;
            var jsonOut = SharedOptions.OutputJson;

            cmd.AddOption(seconds);
            cmd.AddOption(purgeExpired);
            cmd.AddOption(purgeRevoked);
            cmd.AddOption(adminUrl);
            cmd.AddOption(adminToken);
            cmd.AddOption(jsonOut);

            cmd.SetHandler(async (int older, bool expired, bool revoked, string url, string? token, bool json) =>
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
                    var ok = await client.PurgeRefreshTokens(older, expired, revoked);

                    if (json)
                    {
                        if (ok)
                        {
                            var result = new MessageResponse(true, "Refresh token purge completed.");
                            Console.WriteLine(JsonSerializer.Serialize(result, MadJsonContext.Default.MessageResponse));
                        }
                        else
                        {
                            var result = new ErrorResponse(false, "Refresh token purge failed.");
                            Console.WriteLine(JsonSerializer.Serialize(result, MadJsonContext.Default.ErrorResponse));
                        }
                    }
                    else
                    {
                        Console.WriteLine(ok
                            ? "Refresh token purge completed."
                            : "Refresh token purge failed.");
                    }
                }
                catch (Exception ex)
                {
                    var err = new ErrorResponse(false, $"Error purging refresh tokens: {ex.Message}");
                    if (json)
                        Console.WriteLine(JsonSerializer.Serialize(err, MadJsonContext.Default.ErrorResponse));
                    else
                    {
                        Console.Error.WriteLine(err.Message);
                    }
                }
            }, seconds, purgeExpired, purgeRevoked, adminUrl, adminToken, jsonOut);

            return cmd;
        }
    }
}
