using madJwtInspector;
using System.CommandLine;
using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;

namespace mad.Commands
{
    internal static class TokenCommand
    {
        public static Command Build()
        {
            var cmd = new Command("token", "Decode and inspect a JWT");

            var tokenOpt = new Option<string>(
                "--token",
                "The JWT string to decode")
            {
                IsRequired = true
            };

            cmd.AddOption(tokenOpt);

            cmd.SetHandler((string token) =>
            {
                var result = JwtInspector.Decode(token);

                if (!result.IsValidFormat)
                {
                    Console.Error.WriteLine($"Error: {result.ErrorMessage}");
                    return;
                }

                Console.WriteLine("=== Header ===");
                foreach (var (key, val) in result.Header)
                    Console.WriteLine($"{key}: {val}");

                Console.WriteLine("\n=== Payload ===");
                foreach (var (key, val) in result.Payload)
                    Console.WriteLine($"{key}: {val}");

                Console.WriteLine("\n=== Signature ===");
                Console.WriteLine(result.Signature);
            }, tokenOpt);

            return cmd;
        }
    }
}
