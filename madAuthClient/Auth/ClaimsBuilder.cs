using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using madTypes.Api.Responses;

namespace madAuthClient.Auth;

public static class ClaimsBuilder
{
    /// <summary>
    /// Builds a set of claims from the access token and optional user info.
    /// </summary>
    public static List<Claim> FromToken(TokenResponse token, MeResponse? userInfo = null)
    {
        var claims = new List<Claim>();

        // Parse token to extract base claims (sub, exp, etc.)
        var handler = new JwtSecurityTokenHandler();
        if (handler.ReadToken(token.AccessToken) is JwtSecurityToken jwt)
        {
            foreach (var c in jwt.Claims)
            {
                if (claims.All(existing => existing.Type != c.Type))
                    claims.Add(c);
            }
        }

        // Add from user info, if available
        if (userInfo is not null)
        {
            claims.Add(new Claim("username", userInfo.Subject));
            if (!string.IsNullOrWhiteSpace(userInfo.Email))
                claims.Add(new Claim(ClaimTypes.Email, userInfo.Email));

            foreach (var role in userInfo.Roles)
                claims.Add(new Claim(ClaimTypes.Role, role));

            foreach (var scope in userInfo.Scopes)
                claims.Add(new Claim("scope", scope));
        }
                
        return claims;
    }
}
