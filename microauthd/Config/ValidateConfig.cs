using microauthd.Common;
using Serilog;

namespace microauthd.Config
{
    public static class ValidateConfig
    {
        public static bool ValidateAuthConfig(AppConfig config)
        {
            if (string.IsNullOrWhiteSpace(config.AuthIp))
            {
                Log.Fatal("Auth IP cannot be blank.");
                Console.Error.WriteLine("Auth IP cannot be blank.");
                return false;
            }

            if (!Utils.IsValidIpAddress(config.AuthIp))
            {
                Log.Fatal("Auth IP must be a valid ip address.");
                Console.Error.WriteLine("Auth IP must be a valid ip address.");
                return false;
            }

            if (config.AuthPort < 1 || config.AuthPort > 65535)
            {
                Log.Fatal("Auth port must be between 1 and 65535.");
                Console.Error.WriteLine("Auth port must be between 1 and 65535.");
                return false;
            }

            return true;
        }

        public static bool ValidateAdminConfig(AppConfig config)
        {
            if (string.IsNullOrWhiteSpace(config.AdminIp))
            {
                Log.Fatal("Admin IP cannot be blank.");
                Console.Error.WriteLine("Admin IP cannot be blank.");
                return false;
            }

            if (!Utils.IsValidIpAddress(config.AdminIp))
            {
                Log.Fatal("Admin IP must be a valid ip address.");
                Console.Error.WriteLine("Admin IP must be a valid ip address.");
                return false;
            }

            if (config.AdminPort < 1 || config.AdminPort > 65535)
            {
                Log.Fatal("Admin port must be between 1 and 65535.");
                Console.Error.WriteLine("Admin port must be between 1 and 65535.");
                return false;
            }

            return true;
        }
    }
}
