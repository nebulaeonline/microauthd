using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using Serilog;

using microauthd.Config;
using microauthd.Common;

namespace microauthd.Tokens;

public static class TokenIssuer
{
    public record TokenInfo(
        string Token,
        string Jti,
        DateTime IssuedAt,
        DateTime ExpiresAt,
        string UserId,
        string TokenUse
    );

    /// <summary>
    /// Issues a JSON Web Token (JWT) for a user based on the provided configuration, claims, and role.
    /// </summary>
    /// <remarks>The token is signed using either RSA or ECDSA algorithms, depending on the type of private
    /// key in use.  The token includes standard claims such as the unique identifier (JTI), issued-at time (IAT),
    /// and audience (AUD),  as well as a custom claim indicating the token's intended use ("auth" or
    /// "admin").</remarks>
    /// <param name="config">The application configuration containing token expiration settings and issuer information.</param>
    /// <param name="userClaims">A collection of claims associated with the user for whom the token is being issued.</param>
    /// <param name="isAdmin">A value indicating whether the token is being issued for an administrator.  If <see langword="true"/>, the token
    /// will have a longer expiration time and an "admin" role.</param>
    /// <returns>A <see cref="TokenInfo"/> object containing the issued token, its unique identifier (JTI),  the issuance and
    /// expiration times, the user ID, and the token's intended use.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the private key used for signing the token is of an unsupported type.</exception>
    public static TokenInfo IssueToken(AppConfig config, IEnumerable<Claim> userClaims, bool isAdmin, string? audience = null)
    {
        var key = TokenKeyCache.GetPrivateKey(isAdmin);
        var signingCredentials = key switch
        {
            RSA rsa => new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256),
            ECDsa ec => new SigningCredentials(new ECDsaSecurityKey(ec), SecurityAlgorithms.EcdsaSha256),
            _ => throw new InvalidOperationException("Unsupported key type")
        };

        var userId = userClaims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Sub)?.Value ?? "unknown";
        var now = DateTime.UtcNow;
        var expires = now.AddSeconds(isAdmin ? config.AdminTokenExpiration : config.TokenExpiration);
        var jti = Guid.NewGuid().ToString("N");
        var tokenUse = isAdmin ? "admin" : "auth";
        var aud = audience ?? "microauthd";

        // Base claims (ignore Aud as claim — it’s redundant)
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, userClaims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Sub)?.Value ?? "unknown"),
            new(JwtRegisteredClaimNames.Jti, jti),
            new(JwtRegisteredClaimNames.Iat, ((DateTimeOffset)now).ToUnixTimeSeconds().ToString()),
            new("token_use", tokenUse)
        };

        // Propagate other claims, including client_id
        foreach (var c in userClaims)
        {
            if (claims.All(existing => existing.Type != c.Type))
                claims.Add(c);
        }

        var jwt = new JwtSecurityToken(
            issuer: config.OidcIssuer,
            audience: aud,
            claims: claims,
            notBefore: now,
            expires: expires,
            signingCredentials: signingCredentials
        );

        var token = new JwtSecurityTokenHandler().WriteToken(jwt);

        return new TokenInfo(token, jti, now, expires, userId, tokenUse);
    }
}
