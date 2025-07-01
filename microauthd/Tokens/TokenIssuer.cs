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
        string MadUse,
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
        var madUse = isAdmin ? "admin" : "auth";
        var aud = audience;

        // Base claims (ignore Aud as claim — it’s redundant)
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, userClaims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Sub)?.Value ?? "unknown"),
            new(JwtRegisteredClaimNames.Jti, jti),
            new(JwtRegisteredClaimNames.Iat, ((DateTimeOffset)now).ToUnixTimeSeconds().ToString()),
            new("mad", madUse),
            new("token_use", "access")
        };

        // Propagate other claims, including client_id
        foreach (var c in userClaims)
        {
            if (claims.All(existing => existing.Type != c.Type))
                claims.Add(c);
        }

        // Set the JWT header
        var header = new JwtHeader(signingCredentials);
        header["typ"] = "JWT";

        var jwt = new JwtSecurityToken(
            header,
            payload: new JwtPayload(
                issuer: config.OidcIssuer,
                audience: aud,
                claims: claims,
                notBefore: now,
                expires: expires,
                issuedAt: now
            )
        );

        var token = new JwtSecurityTokenHandler().WriteToken(jwt);

        return new TokenInfo(token, jti, now, expires, userId, madUse, "access");
    }

    /// <summary>
    /// Issues an OpenID Connect (OIDC) ID token for the specified user and client.
    /// </summary>
    /// <remarks>The issued ID token is signed using the application's private key and includes standard OIDC
    /// claims such as <see cref="JwtRegisteredClaimNames.Sub"/>, <see cref="JwtRegisteredClaimNames.Iss"/>, <see
    /// cref="JwtRegisteredClaimNames.Aud"/>, <see cref="JwtRegisteredClaimNames.Iat"/>, and <see
    /// cref="JwtRegisteredClaimNames.Exp"/>. The token is valid for 10 minutes, as recommended by OIDC for short-lived
    /// ID tokens. Additional claims such as <see cref="JwtRegisteredClaimNames.Email"/> and "email_verified" are
    /// included if present in <paramref name="userClaims"/>.</remarks>
    /// <param name="config">The application configuration containing OIDC issuer information.</param>
    /// <param name="userClaims">A collection of claims associated with the user. Must include a claim with the type <see
    /// cref="JwtRegisteredClaimNames.Sub"/> to identify the subject.</param>
    /// <param name="clientId">The client identifier for which the token is issued. This is used as the audience of the token.</param>
    /// <returns>A string representation of the issued ID token in JWT format.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the application's private key is of an unsupported type.</exception>
    public static string IssueIdToken(AppConfig config, IEnumerable<Claim> userClaims, string clientId, string? nonce = null)
    {
        var key = TokenKeyCache.GetPrivateKey(isAdmin: false);
        var signingCredentials = key switch
        {
            RSA rsa => new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256),
            ECDsa ec => new SigningCredentials(new ECDsaSecurityKey(ec), SecurityAlgorithms.EcdsaSha256),
            _ => throw new InvalidOperationException("Unsupported key type")
        };

        var now = DateTime.UtcNow;
        var expires = now.AddMinutes(10); // OIDC recommends short-lived ID tokens
        var sub = userClaims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Sub)?.Value ?? "unknown";

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, sub),
            new(JwtRegisteredClaimNames.Iss, config.OidcIssuer),
            new(JwtRegisteredClaimNames.Aud, clientId),
            new(JwtRegisteredClaimNames.Iat, ((DateTimeOffset)now).ToUnixTimeSeconds().ToString()),
            new(JwtRegisteredClaimNames.Exp, ((DateTimeOffset)expires).ToUnixTimeSeconds().ToString()),
            new("token_use", "id"),
            new("mad", "id"),
            new("auth_time", ((DateTimeOffset)DateTime.UtcNow).ToUnixTimeSeconds().ToString())
        };

        // email + email_verified if present
        foreach (var c in userClaims)
        {
            if (c.Type is JwtRegisteredClaimNames.Email or "email_verified")
                claims.Add(c);
        }

        // add nonce if present
        if (!string.IsNullOrEmpty(nonce))
            claims.Add(new Claim("nonce", nonce));

        var header = new JwtHeader(signingCredentials);
        header["typ"] = "JWT";

        var jwt = new JwtSecurityToken(
            header,
            payload: new JwtPayload(
                issuer: config.OidcIssuer,
                audience: clientId,
                claims: claims,
                notBefore: now,
                expires: expires,
                issuedAt: now
            )
        );

        return new JwtSecurityTokenHandler().WriteToken(jwt);
    }

}
