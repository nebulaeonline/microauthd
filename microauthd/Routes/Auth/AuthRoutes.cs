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
            var version = typeof(Program).Assembly.GetName().Version?.ToString() ?? "unknown";
            return Results.Ok(new { version });
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

            var roles = user.FindAll(ClaimTypes.Role)
                            .Select(r => r.Value)
                            .ToList();

            var me = new MeResponse(sub, email, roles);
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

            var request = new TokenRequest
            {
                Username = form["username"],
                Password = form["password"],
                ClientIdentifier = form["client_id"]
            };

            if (string.IsNullOrWhiteSpace(request.Username) ||
                string.IsNullOrWhiteSpace(request.Password) ||
                string.IsNullOrWhiteSpace(request.ClientIdentifier))
            {
                return ApiResult<TokenResponse>
                    .Fail("Invalid credentials", 400)
                    .ToHttpResult();
            }

            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var ua = ctx.Request.Headers["User-Agent"].FirstOrDefault() ?? "unknown";

            return AuthService.IssueUserToken(request, config, ip, ua).ToHttpResult();
        })
        .WithName("IssueToken")
        .Produces<TokenResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status403Forbidden)
        .WithTags("Auth")
        .WithOpenApi();


        // refresh token request endpoint (if enabled)**********************************************
        if (config.EnableTokenRefresh)
        {
            group.MapPost("/token/refresh", (RefreshRequest req, AppConfig config) =>
            {
                return AuthService.RefreshAccessToken(req, config).ToHttpResult();
            })
            .WithName("RefreshToken")
            .Produces<TokenResponse>(StatusCodes.Status200OK)
            .Produces<ErrorResponse>(StatusCodes.Status403Forbidden)
            .WithTags("Refresh Token")
            .WithOpenApi();
        }

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
        .Produces<MessageResponse>(StatusCodes.Status200OK)
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
        // OIDC token introspection endpoint (machine-to-machine only)
        group.MapPost("/introspect", async (HttpContext ctx, AppConfig config) =>
        {
            // Require valid form
            if (!ctx.Request.HasFormContentType)
            {
                AuditLogger.AuditLog(
                    config: config,
                    userId: null,
                    action: "token.introspect.failure",
                    target: $"client=invalid reason=invalid_form",
                    ipAddress: ctx.Connection.RemoteIpAddress?.ToString(),
                    userAgent: ctx.Request.Headers["User-Agent"].FirstOrDefault()
                );

                return ApiResult<Dictionary<string, object>>
                    .Fail("Authorization Failed", 403)
                    .ToHttpResult();
            }

            var form = await ctx.Request.ReadFormAsync();
            var token = form["token"].FirstOrDefault();

            if (string.IsNullOrWhiteSpace(token))
            {
                AuditLogger.AuditLog(
                    config: config,
                    userId: null,
                    action: "token.introspect.failure",
                    target: $"client=unknown reason=null_token",
                    ipAddress: ctx.Connection.RemoteIpAddress?.ToString(),
                    userAgent: ctx.Request.Headers["User-Agent"].FirstOrDefault()
                );

                return ApiResult<Dictionary<string, object>>
                    .Fail("Authorization Failed", 403)
                    .ToHttpResult();
            }

            // Require client credentials via HTTP Basic Auth
            var authHeader = ctx.Request.Headers.Authorization.ToString();
            if (!AuthHelpers.TryParseBasicAuth(authHeader, out var clientId, out var clientSecret))
            {
                AuditLogger.AuditLog(
                    config: config,
                    userId: null,
                    action: "token.introspect.failure",
                    target: $"client={clientId} reason=unable_to_parse_auth",
                    ipAddress: ctx.Connection.RemoteIpAddress?.ToString(),
                    userAgent: ctx.Request.Headers["User-Agent"].FirstOrDefault()
                );
                return ApiResult<Dictionary<string, object>>
                    .Fail("Authorization Failed", 403)
                    .ToHttpResult();
            }

            // Authenticate the client (supports both in-memory and DB clients)
            var client = AuthService.AuthenticateClient(clientId, clientSecret, config);
            if (client is null)
            {
                AuditLogger.AuditLog(
                    config: config,
                    userId: null,
                    action: "token.introspect.failure",
                    target: $"client={clientId} reason=failed_basic_auth",
                    ipAddress: ctx.Connection.RemoteIpAddress?.ToString(),
                    userAgent: ctx.Request.Headers["User-Agent"].FirstOrDefault()
                );

                return ApiResult<Dictionary<string, object>>
                    .Fail("Authorization Failed", 403)
                    .ToHttpResult();
            }

            // Delegate to token introspection logic
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

        return group;
    }
}
