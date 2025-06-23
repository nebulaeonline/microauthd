using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;

namespace madClient.Auth
{
    public class TokenValidator
    {
        private readonly HttpClient _http;
        private readonly string _jwksUrl;
        private JsonWebKeySet? _cachedJwks;
        private DateTime _jwksFetchedAt = DateTime.MinValue;
        private readonly TimeSpan _jwksTtl = TimeSpan.FromMinutes(10);

        public TokenValidator(string baseAuthUrl, HttpClient? httpClient = null)
        {
            _jwksUrl = $"{baseAuthUrl.TrimEnd('/')}/.well-known/jwks.json";
            _http = httpClient ?? new HttpClient();
        }

        private async Task<JsonWebKeySet> GetJwksAsync()
        {
            if (_cachedJwks != null && DateTime.UtcNow - _jwksFetchedAt < _jwksTtl)
                return _cachedJwks;

            var json = await _http.GetStringAsync(_jwksUrl);
            _cachedJwks = new JsonWebKeySet(json);
            _jwksFetchedAt = DateTime.UtcNow;
            return _cachedJwks;
        }

        public async Task<ClaimsPrincipal?> ValidateTokenAsync(string token, bool validateLifetime = true)
        {
            var jwks = await GetJwksAsync();

            var handler = new JwtSecurityTokenHandler();
            var parameters = new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                RequireSignedTokens = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = jwks.Keys,
                ValidateLifetime = validateLifetime,
                ClockSkew = TimeSpan.FromSeconds(30)
            };

            try
            {
                var principal = handler.ValidateToken(token, parameters, out var _);
                return principal;
            }
            catch (SecurityTokenException)
            {
                return null;
            }
        }

        public static bool HasScope(ClaimsPrincipal user, string requiredScope)
        {
            var scopes = user.Claims
                .Where(c => c.Type == "scope")
                .SelectMany(s => s.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries));

            return scopes.Contains(requiredScope, StringComparer.OrdinalIgnoreCase);
        }

        public static bool HasRole(ClaimsPrincipal user, string requiredRole)
        {
            return user.Claims
                .Where(c => c.Type == "role")
                .Select(c => c.Value)
                .Contains(requiredRole, StringComparer.OrdinalIgnoreCase);
        }

        public static string? GetUserId(ClaimsPrincipal user)
        {
            return user.Claims.FirstOrDefault(c => c.Type == "sub")?.Value;
        }
    }
}
