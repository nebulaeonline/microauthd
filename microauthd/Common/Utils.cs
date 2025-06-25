using microauthd.Config;
using microauthd.Logging;
using nebulae.dotArgon2;
using System.Net;
using System.Net.Mail;
using System.Security.Cryptography;
using System.Text;

namespace microauthd.Common
{
    public static class Utils
    {
        public static IServiceProvider Services { get; private set; } = null!;
        public static void Init(IServiceProvider services) => Services = services;
        public static AuditDos Audit => Services.GetRequiredService<AuditDos>();

        /// <summary>
        /// Determines whether the specified string is a valid IP address.
        /// </summary>
        /// <remarks> This method returns <see langword="false"/> if the input is <see langword="null"/>,
        /// empty, or consists only of whitespace. </remarks>
        /// <param name="input">The string to validate as an IP address. Can be either IPv4 or IPv6 format.</param>
        /// <returns><see langword="true"/> if the specified string is a valid IP address; otherwise, <see langword="false"/>. </returns>
        public static bool IsValidIpAddress(string? input)
        {
            if (string.IsNullOrWhiteSpace(input))
                return false;

            return IPAddress.TryParse(input, out _);
        }

        /// <summary>
        /// Determines whether the specified string is a valid email address.
        /// </summary>
        /// <remarks>This method checks the format of the email address and ensures it adheres  to
        /// standard email address conventions. It does not verify the existence of  the email address or its
        /// domain.</remarks>
        /// <param name="input">The email address to validate. Cannot be null.</param>
        /// <returns>true if the specified string is a valid email address;  otherwise, false. </returns>
        public static bool IsValidEmail(string input)
        {
            try
            {
                var addr = new MailAddress(input);
                return addr.Address == input;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Determines whether the specified integer is a power of two.
        /// </summary>
        /// <remarks>A power of two is any positive integer that can be expressed as 2 raised to an
        /// integer exponent. For example, 1, 2, 4, 8, and 16 are powers of two.</remarks>
        /// <param name="n">The integer to evaluate. Must be non-negative.</param>
        /// <returns><see langword="true"/> if <paramref name="n"/> is a power of two; otherwise, <see langword="false"/>.</returns>
        public static bool IsPowerOfTwo(int n) => n > 0 && (n & (n - 1)) == 0;

        /// <summary>
        /// Generates a URL-safe Base64-encoded string from a specified number of random bytes.
        /// </summary>
        /// <remarks>This method uses a cryptographically secure random number generator to produce the
        /// random bytes. The resulting Base64 string is suitable for use in URLs or other contexts where standard
        /// Base64  encoding characters may cause issues.</remarks>
        /// <param name="bytesToGenerate">The number of random bytes to generate. Must be greater than zero.</param>
        /// <returns>A Base64-encoded string representing the generated random bytes. The string is URL-safe,  with padding
        /// removed and characters '+' and '/' replaced by '-' and '_', respectively.</returns>
        public static string GenerateBase64EncodedRandomBytes(int bytesToGenerate)
        {
            var bytes = new byte[bytesToGenerate];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(bytes);

            // URL-safe base64: strip padding and avoid "+" and "/"
            return Convert.ToBase64String(bytes)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
        }

        /// <summary>
        /// Generates a cryptographically secure random salt of the specified length.
        /// </summary>
        /// <param name="length">The length of the salt to generate, in bytes. Must be a positive integer.</param>
        /// <returns>A byte array containing the generated salt.</returns>
        public static byte[] GenerateSalt(int length)
        {
            var salt = new byte[length];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(salt);
            return salt;
        }

        /// <summary>
        /// Encodes the specified byte array into a Base64 URL-safe string.
        /// </summary>
        /// <remarks>This method produces a Base64-encoded string that is safe for use in URLs and
        /// filenames by replacing characters that are not URL-safe ('+' and '/') with '-' and '_', and by omitting
        /// padding characters ('=').</remarks>
        /// <param name="data">The byte array to encode. Must not be <see langword="null"/>.</param>
        /// <returns>A Base64 URL-safe string representation of the input byte array. The string is encoded without padding and
        /// uses '-' and '_' in place of '+' and '/'.</returns>
        public static string Base64Url(byte[] data) =>
            Convert.ToBase64String(data)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');

        /// <summary>
        /// Computes the SHA-256 hash of the specified input string and returns the result as a URL-safe Base64-encoded
        /// string.
        /// </summary>
        /// <remarks>This method produces a Base64-encoded string that is safe for use in URLs by omitting
        /// padding  characters and replacing characters that are not URL-friendly. It is suitable for scenarios  where
        /// the hash needs to be transmitted or stored in a URL-safe format.</remarks>
        /// <param name="input">The input string to hash. Cannot be <see langword="null"/> or empty.</param>
        /// <returns>A URL-safe Base64-encoded string representation of the SHA-256 hash of the input. The string does not
        /// include padding characters ('=') and replaces '+' with '-' and '/' with '_'.</returns>
        public static string Sha256Base64(string input)
        {
            using var sha = SHA256.Create();
            var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(input));
            return Convert.ToBase64String(hash)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_'); // URL-safe
        }

        /// <summary>
        /// Reads user input from the console while masking the input with asterisks.
        /// </summary>
        /// <remarks>This method captures input character by character, displaying an asterisk (*) for
        /// each character entered. Backspace is supported, allowing the user to delete the last entered character.
        /// Input is terminated when the Enter key is pressed.</remarks>
        /// <returns>A <see cref="string"/> containing the user's input, excluding the masking asterisks.</returns>
        public static string ReadHiddenInput()
        {
            var result = new StringBuilder();
            ConsoleKeyInfo key;
            while ((key = Console.ReadKey(intercept: true)).Key != ConsoleKey.Enter)
            {
                if (key.Key == ConsoleKey.Backspace && result.Length > 0)
                {
                    result.Length--;
                    Console.Write("\b \b");
                }
                else if (!char.IsControl(key.KeyChar))
                {
                    result.Append(key.KeyChar);
                    Console.Write("*");
                }
            }
            Console.WriteLine();
            return result.ToString();
        }

        // Valid tokens must not contain whitespace and cannot be null or empty.
        public static bool IsValidTokenName(string input)
        {
            return !string.IsNullOrWhiteSpace(input)
                && input.All(c => !char.IsWhiteSpace(c));
        }

        /// <summary>
        /// Generates a random Base32-encoded secret.
        /// </summary>
        /// <remarks>This method uses a cryptographically secure random number generator to produce the
        /// random bytes. The resulting string is encoded using the Base32 encoding scheme, which is commonly used for
        /// secrets in applications such as two-factor authentication.</remarks>
        /// <param name="numBytes">The number of random bytes to generate. Must be a positive integer. Defaults to 20.</param>
        /// <returns>A Base32-encoded string representing the generated random bytes.</returns>
        public static string GenerateBase32Secret(int numBytes = 20)
        {
            var bytes = new byte[numBytes];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(bytes);

            return Base32Encode(bytes);
        }

        /// <summary>
        /// Encodes the specified byte array into a Base32 string representation.
        /// </summary>
        /// <remarks>This method uses the standard Base32 alphabet (A-Z, 2-7) without padding.  The
        /// resulting string is case-insensitive and suitable for use in scenarios  where a compact, human-readable
        /// encoding is required.</remarks>
        /// <param name="data">The byte array to encode. Cannot be null or empty.</param>
        /// <returns>A Base32-encoded string representation of the input byte array.</returns>
        private static string Base32Encode(byte[] data)
        {
            const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

            var result = new StringBuilder();
            int buffer = data[0];
            int next = 1;
            int bitsLeft = 8;

            while (bitsLeft > 0 || next < data.Length)
            {
                if (bitsLeft < 5)
                {
                    if (next < data.Length)
                    {
                        buffer <<= 8;
                        buffer |= data[next++] & 0xff;
                        bitsLeft += 8;
                    }
                    else
                    {
                        int pad = 5 - bitsLeft;
                        buffer <<= pad;
                        bitsLeft += pad;
                    }
                }

                int index = (buffer >> (bitsLeft - 5)) & 0x1f;
                bitsLeft -= 5;
                result.Append(alphabet[index]);
            }

            return result.ToString(); // no padding
        }

        /// <summary>
        /// Generates a random hexadecimal string of the specified length in bytes.
        /// </summary>
        /// <param name="numBytes">The number of random bytes to generate. Must be a non-negative integer.</param>
        /// <returns>A lowercase hexadecimal string representing the generated random bytes.</returns>
        public static string RandHex(int numBytes)
        {
            var bytes = new byte[numBytes];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(bytes);
            return Convert.ToHexString(bytes).ToLowerInvariant();
        }

        /// <summary>
        /// Retrieves the actual client IP address, accounting for trusted X-Forwarded-For headers.
        /// </summary>
        /// <param name="ctx">The current HTTP context.</param>
        /// <returns>The best-effort IP address of the client as a string.</returns>
        public static string GetRealIp(HttpContext ctx)
        {
            // Check for X-Forwarded-For (if UseForwardedHeaders applied it)
            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";

            // Defensive fallback: if the forwarded IP is available manually, use first hop
            var forwarded = ctx.Request.Headers["X-Forwarded-For"].FirstOrDefault();
            if (!string.IsNullOrWhiteSpace(forwarded))
            {
                var parts = forwarded.Split(',', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length > 0 && IsValidIpAddress(parts[0]))
                    return parts[0].Trim();
            }

            return ip;
        }
    }
}
