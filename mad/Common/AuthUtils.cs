using System.Security.Cryptography;
using System.Text;

namespace mad.Common;

public static class AuthUtils
{
    private static readonly string TokenPath =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".mad_token");

    public static string? TryLoadToken()
    {
        try
        {
            if (!File.Exists(TokenPath))
                return null;

            var token = File.ReadAllText(TokenPath).Trim();
            return string.IsNullOrWhiteSpace(token) ? null : token;
        }
        catch
        {
            return null; // unreadable or corrupt
        }
    }

    public static bool SaveToken(string token)
    {
        try
        {
            File.WriteAllText(TokenPath, token);
            return true;
        }
        catch
        {
            return false;
        }
    }

    public static bool DeleteToken()
    {
        try
        {
            if (File.Exists(TokenPath))
                File.Delete(TokenPath);

            return true;
        }
        catch
        {
            return false;
        }
    }

    public static string GeneratePassword(int length)
    {
        if (length < 8)
            throw new ArgumentOutOfRangeException(nameof(length), "Minimum length is 8 characters.");

        const string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}";
        var password = new StringBuilder(length);
        var bytes = new byte[length];

        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(bytes);

        for (int i = 0; i < length; i++)
        {
            var idx = bytes[i] % charset.Length;
            password.Append(charset[idx]);
        }

        return password.ToString();
    }
}
