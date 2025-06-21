using madTypes.Api.Common;
using madTypes.Api.Requests;
using madTypes.Api.Responses;
using madTypes.Common;
using microauthd.Common;
using microauthd.Config;
using microauthd.Data;
using microauthd.Services;
using microauthd.Tokens;
using Microsoft.IdentityModel.Tokens;
using nebulae.dotArgon2;
using Serilog;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using static nebulae.dotArgon2.Argon2;

namespace microauthd.Routes.Auth;

public static class AuthRoutes
{
    public static RouteGroupBuilder MapAuthRoutes(this IEndpointRouteBuilder routes, AppConfig config)
    {
        var group = routes.MapGroup("");

        // ping endpoint****************************************************************************
        group.MapGet("/ping", () =>
        {
            var ping = new PingResponse("pong from auth");
            return Results.Json(ping, MicroauthJsonContext.Default.PingResponse);
        })
        .WithTags("Info")
        .WithOpenApi();

        // version endpoint*************************************************************************
        group.MapGet("/version", () =>
        {
            var response = new VersionResponse();
            return Results.Json(response, MicroauthJsonContext.Default.VersionResponse);
        })
        .WithTags("Info")
        .WithOpenApi();

        // me endpoint******************************************************************************
        group.MapGet("/me", (ClaimsPrincipal user) =>
        {
            var sub = user.FindFirst(ClaimTypes.NameIdentifier)?.Value
                   ?? user.FindFirst(JwtRegisteredClaimNames.Sub)?.Value
                   ?? "unknown";

            var email = user.FindFirst(ClaimTypes.Email)?.Value
                     ?? user.FindFirst("email")?.Value;

            var roles = user.FindAll("role")
                            .Select(r => r.Value)
                            .ToList();

            var scopeClaim = user.Claims.FirstOrDefault(c => c.Type == "scope")?.Value;
            var scopes = string.IsNullOrEmpty(scopeClaim)
                ? Array.Empty<string>()
                : scopeClaim.Split(' ', StringSplitOptions.RemoveEmptyEntries);

            var me = new MeResponse(sub, email, roles, scopes.ToList());
            return Results.Json(me, MicroauthJsonContext.Default.MeResponse);
        })
        .RequireAuthorization()
        .WithTags("me")
        .WithOpenApi();

        // obtain user sessions endpoint************************************************************
        group.MapGet("/me/sessions", (ClaimsPrincipal user) =>
        {
            var userId = user.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
            return UserService.GetSessionsForSelf(userId!).ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("GetMySessions")
        .Produces<List<SessionResponse>>(StatusCodes.Status200OK)
        .WithTags("me")
        .WithTags("session")
        .WithOpenApi();

        // me refresh tokens endpoint***************************************************************
        if (config.EnableTokenRefresh)
        {
            group.MapGet("/me/refresh-tokens", (ClaimsPrincipal user) =>
            {
                var userId = user.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
                return UserService.GetRefreshTokensForSelf(userId).ToHttpResult();
            })
            .RequireAuthorization()
            .WithName("GetMyRefreshTokens")
            .Produces<List<RefreshTokenResponse>>(StatusCodes.Status200OK)
            .WithTags("me")
            .WithTags("Refresh Token")
            .WithOpenApi();
        }

        // whoami endpoint**************************************************************************
        group.MapGet("/whoami", (ClaimsPrincipal user) =>
        {
            return UserService.GetIdentitySummary(user).ToHttpResult();
        })
        .RequireAuthorization()
        .WithTags("Info")
        .WithTags("me")
        .WithOpenApi();

        // token request endpoint*******************************************************************
        group.MapPost("/token", async (AppConfig config, HttpContext ctx) =>
        {
            if (!ctx.Request.HasFormContentType)
                return ApiResult<TokenResponse>
                    .Fail("Invalid credentials", 400)
                    .ToHttpResult();

            var form = await ctx.Request.ReadFormAsync();
            var grantType = form["grant_type"].ToString().Trim();
                            
            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var ua = ctx.Request.Headers["User-Agent"].FirstOrDefault() ?? "unknown";

            return grantType switch
            {
                "password" => AuthService.IssueUserToken(
                    form, 
                    config, 
                    ip, 
                    ua)
                .ToHttpResult(),
                
                "refresh_token" => AuthService.RefreshAccessToken(
                    form, 
                    config)
                .ToHttpResult(),
                
                _ => ApiResult<TokenResponse>.Fail("Unsupported grant_type", 400).ToHttpResult()
            };            
        })
        .WithName("IssueToken")
        .Produces<TokenResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status403Forbidden)
        .WithTags("Auth")
        .WithOpenApi();

        // user logout endpoint*********************************************************************
        group.MapPost("/logout", (ClaimsPrincipal user, AppConfig config) =>
        {
            var userId = user.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
            var clientIdentifier = user.FindFirst("client_id")?.Value;

            if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(clientIdentifier))
                return ApiResult<MessageResponse>.Fail("Missing user or client identifier", 400).ToHttpResult();

            return AuthService.Logout(userId, clientIdentifier, config).ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("Logout")
        .WithTags("Auth")
        .WithOpenApi();

        // logout of all sessions endpoint**********************************************************
        group.MapPost("/logout-all", (ClaimsPrincipal user, AppConfig config) =>
        {
            var userId = user.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;

            if (string.IsNullOrWhiteSpace(userId))
                return ApiResult<MessageResponse>.Fail("Missing user identifier", 400).ToHttpResult();

            return AuthService.LogoutAll(userId, config).ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("LogoutAll")
        .WithTags("Auth")
        .WithOpenApi();

        // OIDC well-known endpoint*****************************************************************
        group.MapGet("/.well-known/openid-configuration", (AppConfig config) =>
        {
            return AuthService.GetDiscoveryDocument(config).ToHttpResult();
        })
        .WithName("OidcDiscovery")
        .WithTags("OIDC")
        .Produces(StatusCodes.Status200OK)
        .WithTags("OIDC")
        .WithOpenApi();

        // JWKS endpoint****************************************************************************
        group.MapGet("/jwks.json", () =>
        {
            return AuthService.GetJwks().ToHttpResult();
        })
        .WithName("JwksDocument")
        .WithTags("OIDC")
        .Produces<JwksResponse>(StatusCodes.Status200OK)
        .WithOpenApi();

        // OIDC token endpoint**********************************************************************
        group.MapPost("/oidc/token", async (HttpContext ctx, AppConfig config) =>
        {
            if (!ctx.Request.HasFormContentType)
                return ApiResult<TokenResponse>.Fail("Invalid content type", 400).ToHttpResult();

            var form = await ctx.Request.ReadFormAsync();
            return AuthService.IssueOidcToken(form, config).ToHttpResult();
        })
        .Produces<TokenResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .WithName("OidcToken")
        .WithTags("OIDC")
        .WithOpenApi();

        // provision user endpoint******************************************************************
        group.MapPost("/user", (ClaimsPrincipal user, CreateUserRequest req, AppConfig config, HttpContext ctx) =>
        {
            return UserService.CreateUserScoped(
                actingUser: user,
                request: req,
                config: config,
                ipAddress: ctx.Connection.RemoteIpAddress?.ToString(),
                userAgent: ctx.Request.Headers["User-Agent"].FirstOrDefault()
            ).ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("ProvisionUser")
        .Produces<UserObject>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .Produces<ErrorResponse>(StatusCodes.Status403Forbidden)
        .WithTags("Auth")
        .WithOpenApi();

        // reset user password endpont**************************************************************
        group.MapPost("/user/{id}/reset", (
            ClaimsPrincipal user,
            string id,
            ResetPasswordRequest req,
            AppConfig config,
            HttpContext ctx) =>
        {
            return UserService.ResetUserPasswordScoped(
                actingUser: user,
                targetUserId: id,
                newPassword: req.NewPassword,
                config: config,
                ipAddress: ctx.Connection.RemoteIpAddress?.ToString(),
                userAgent: ctx.Request.Headers["User-Agent"].FirstOrDefault()
            ).ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("ResetUserPasswordScoped")
        .Produces<MessageResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .Produces<ErrorResponse>(StatusCodes.Status403Forbidden)
        .WithTags("Auth")
        .WithOpenApi();

        // deactivate user endpoint*****************************************************************
        group.MapPost("/user/{id}/deactivate", (
            ClaimsPrincipal user,
            string id,
            AppConfig config,
            HttpContext ctx) =>
        {
            return UserService.DeactivateUserScoped(
                actingUser: user,
                targetUserId: id,
                config: config, 
                ipAddress: ctx.Connection.RemoteIpAddress?.ToString(),
                userAgent: ctx.Request.Headers["User-Agent"].FirstOrDefault()
            ).ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("DeactivateUserScoped")
        .Produces<MessageResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .Produces<ErrorResponse>(StatusCodes.Status403Forbidden)
        .WithTags("Auth")
        .WithOpenApi();

        // retrieve user endpoint*******************************************************************
        group.MapGet("/user/{id}", (
            ClaimsPrincipal user,
            string id,
            HttpContext ctx,
            AppConfig config) =>
        {
            return UserService.GetUserByIdScoped(
                actingUser: user,
                targetUserId: id,
                config: config,
                ipAddress: ctx.Connection.RemoteIpAddress?.ToString(),
                userAgent: ctx.Request.Headers["User-Agent"].FirstOrDefault()
            ).ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("ReadUserScoped")
        .Produces<UserObject>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status403Forbidden)
        .Produces<ErrorResponse>(StatusCodes.Status404NotFound)
        .WithTags("Auth")
        .WithOpenApi();

        // list users endpoint**********************************************************************
        group.MapGet("/users", (
            ClaimsPrincipal user,
            HttpContext ctx,
            AppConfig config) =>
        {
            return UserService.ListUsersScoped(
                actingUser: user,
                config: config,
                ipAddress: ctx.Connection.RemoteIpAddress?.ToString(),
                userAgent: ctx.Request.Headers["User-Agent"].FirstOrDefault()
            ).ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("ListUsersScoped")
        .Produces<List<UserObject>>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status403Forbidden)
        .WithTags("Auth")
        .WithOpenApi();

        // OIDC token introspection endpoint********************************************************
        group.MapPost("/introspect", async (HttpContext ctx, AppConfig config) =>
        {
            // Parse Authorization header (Basic)
            var authHeader = ctx.Request.Headers["Authorization"].FirstOrDefault();
            var basicAuthResult = AuthHelpers.TryParseBasicAuth(authHeader, out string basicClientId, out string basicSecret);

            if (authHeader?.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) == true)
            {
                Log.Warning("Bearer token provided to /introspect endpoint; Basic or form authentication is expected.");
            }

            var form = await ctx.Request.ReadFormAsync();
            var token = form["token"].ToString();
            var clientId = form["client_id"].ToString();
            var clientSecret = form["client_secret"].ToString();

            // Prefer Basic auth values
            if (!string.IsNullOrWhiteSpace(basicClientId))
                clientId = basicClientId;
            if (!string.IsNullOrWhiteSpace(basicSecret))
                clientSecret = basicSecret;

            if (string.IsNullOrWhiteSpace(token) || string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(clientSecret))
            {
                AuditLogger.AuditLog(
                    config,
                    userId: null,
                    action: "token.introspect.failure",
                    target: $"client={clientId} reason=missing_fields",
                    ipAddress: ctx.Connection.RemoteIpAddress?.ToString(),
                    userAgent: ctx.Request.Headers["User-Agent"].FirstOrDefault()
                );

                return ApiResult<Dictionary<string, object>>
                    .Fail("Authorization Failed", 403)
                    .ToHttpResult();
            }

            var client = AuthService.AuthenticateClient(clientId, clientSecret, config);
            if (client is null)
            {
                AuditLogger.AuditLog(
                    config,
                    userId: null,
                    action: "token.introspect.failure",
                    target: $"client={clientId} reason=invalid_client_credentials",
                    ipAddress: ctx.Connection.RemoteIpAddress?.ToString(),
                    userAgent: ctx.Request.Headers["User-Agent"].FirstOrDefault()
                );

                return ApiResult<Dictionary<string, object>>
                    .Fail("Authorization Failed", 403)
                    .ToHttpResult();
            }

            return AuthService.IntrospectToken(
                token,
                client.ClientId,
                ctx.Connection.RemoteIpAddress,
                ctx.Request.Headers["User-Agent"].FirstOrDefault(),
                config).ToHttpResult();
        })
        .WithName("TokenIntrospection")
        .WithTags("OIDC")
        .Produces<Dictionary<string, object>>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status403Forbidden)
        .WithOpenApi();

        // revoke OIDC token endpoint***************************************************************
        group.MapPost("/revoke", async (HttpContext ctx, AppConfig config) =>
        {
            var authHeader = ctx.Request.Headers["Authorization"].FirstOrDefault();
            var basicAuthResult = AuthHelpers.TryParseBasicAuth(authHeader, out string basicClientId, out string basicSecret);
            var form = await ctx.Request.ReadFormAsync();

            if (authHeader?.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) == true)
            {
                Log.Warning("Bearer token provided to /introspect endpoint; Basic or form authentication is expected.");
            }

            var token = form["token"].ToString();
            var clientId = form["client_id"].ToString();
            var clientSecret = form["client_secret"].ToString();

            // Prefer Basic auth
            if (!string.IsNullOrWhiteSpace(basicClientId))
                clientId = basicClientId;
            if (!string.IsNullOrWhiteSpace(basicSecret))
                clientSecret = basicSecret;

            if (string.IsNullOrWhiteSpace(token) || string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(clientSecret))
            {
                return ApiResult<MessageResponse>.Fail("Missing token or credentials", 400).ToHttpResult();
            }

            var client = AuthService.AuthenticateClient(clientId, clientSecret, config);
            if (client is null)
            {
                return ApiResult<MessageResponse>.Fail("Invalid client credentials", 403).ToHttpResult();
            }

            return AuthService.RevokeToken(token).ToHttpResult();
        })
        .WithName("RevokeTokenPublic")
        .WithTags("OIDC")
        .Accepts<IFormCollection>("application/x-www-form-urlencoded")
        .Produces<MessageResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .Produces<ErrorResponse>(StatusCodes.Status403Forbidden)
        .WithOpenApi();

        return group;
    }
}
