using microauthd.Common;
using microauthd.Config;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;

namespace microauthd.Tokens
{
    public static class TokenKeyCache
    {
        private static AsymmetricAlgorithm? _authPrivateKey;
        private static AsymmetricAlgorithm? _adminPrivateKey;

        private static SecurityKey? _authPublicKey;
        private static SecurityKey? _adminPublicKey;

        private static string? _authKeyId;
        private static string? _adminKeyId;

        public static string? GetKeyId(bool isAdmin) =>
            isAdmin ? _adminKeyId : _authKeyId;

        public static void Initialize(AppConfig config, string authCertKeyId, string adminCertKeyId)
        {
            _authPrivateKey = TokenCertManager.LoadPrivateKey(config.TokenSigningKeyFile, config.TokenSigningKeyPassphrase);
            _adminPrivateKey = TokenCertManager.LoadPrivateKey(config.AdminTokenSigningKeyFile, config.AdminTokenSigningKeyPassphrase);

            _authPublicKey = _authPrivateKey switch
            {
                RSA rsa => new RsaSecurityKey(rsa) { KeyId = authCertKeyId },
                ECDsa ec => new ECDsaSecurityKey(ec) { KeyId = authCertKeyId },
                _ => throw new InvalidOperationException("Unsupported key type")
            };

            _adminPublicKey = _adminPrivateKey switch
            {
                RSA rsa => new RsaSecurityKey(rsa) { KeyId = adminCertKeyId },
                ECDsa ec => new ECDsaSecurityKey(ec) { KeyId = adminCertKeyId },
                _ => throw new InvalidOperationException("Unsupported key type")
            };

            _authKeyId = authCertKeyId;
            _adminKeyId = adminCertKeyId;
        }

        public static AsymmetricAlgorithm GetPrivateKey(bool isAdmin) =>
            isAdmin ? _adminPrivateKey! : _authPrivateKey!;

        public static SecurityKey GetPublicKey(bool isAdmin) =>
            isAdmin ? _adminPublicKey! : _authPublicKey!;
    }
}
