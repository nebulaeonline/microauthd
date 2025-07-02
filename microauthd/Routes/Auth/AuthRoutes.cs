using madTypes.Api.Common;
using madTypes.Api.Requests;
using madTypes.Api.Responses;
using madTypes.Common;
using microauthd.Common;
using microauthd.Config;
using microauthd.Data;
using microauthd.Services;
using microauthd.Tokens;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
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
            return Results.Json(ping, MicroauthdJsonContext.Default.PingResponse);
        })
        .AllowAnonymous()
        .WithTags("Info")
        .WithOpenApi();

        // version endpoint*************************************************************************
        group.MapGet("/version", () =>
        {
            var response = new VersionResponse();
            return Results.Json(response, MicroauthdJsonContext.Default.VersionResponse);
        })
        .AllowAnonymous()
        .WithTags("Info")
        .WithOpenApi();

        // anti-forgery endpoint********************************************************************
        group.MapGet("/antiforgery", (IAntiforgery antiforgery, HttpContext ctx) =>
        {
            var tokens = antiforgery.GetAndStoreTokens(ctx);
            ctx.Response.Headers["X-CSRF-TOKEN"] = tokens.RequestToken!;
            return Results.Text(tokens.RequestToken!);
        })
        .AllowAnonymous()
        .WithName("GetAntiforgeryToken")
        .WithTags("Security");

        // user info endpoint***********************************************************************
        group.MapGet("/userinfo", (ClaimsPrincipal user, AppConfig config) =>
        {
            var sub = user.FindFirst(ClaimTypes.NameIdentifier)?.Value
                   ?? user.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;

            if (string.IsNullOrWhiteSpace(sub) || !Guid.TryParse(sub, out _))
                return Results.Unauthorized(); // must be a valid user token

            var scope = user.FindFirst("scope")?.Value;
            if (string.IsNullOrWhiteSpace(scope) || !scope.Split(' ').Contains("openid"))
                return Results.Forbid(); // requires openid scope

            var email = user.FindFirst(ClaimTypes.Email)?.Value;
            var name = user.FindFirst("name")?.Value
                     ?? user.FindFirst("preferred_username")?.Value
                     ?? user.FindFirst(ClaimTypes.Name)?.Value;

            var claims = new Dictionary<string, object>
            {
                ["sub"] = sub,
                ["iss"] = config.OidcIssuer
            };

            var aud = user.FindFirst(JwtRegisteredClaimNames.Aud)?.Value;
            if (!string.IsNullOrWhiteSpace(aud))
                claims["aud"] = aud;

            if (!string.IsNullOrWhiteSpace(email))
                claims["email"] = email;

            if (!string.IsNullOrWhiteSpace(name))
                claims["name"] = name;

            var emailVerified = user.FindFirst("email_verified")?.Value;
            if (emailVerified != null)
                claims["email_verified"] = bool.TryParse(emailVerified, out var v) && v;

            return Results.Json(claims);
        })
        .RequireAuthorization()
        .WithName("UserInfo")
        .WithTags("OIDC")
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
            return Results.Json(me, MicroauthdJsonContext.Default.MeResponse);
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

        // authorize for pkce endpoint**************************************************************
        if (config.EnablePkce)
        {
            group.MapGet("/authorize", (HttpRequest request, HttpContext ctx, AppConfig config) =>
            {
                return AuthService.HandleAuthorizationRequest(request, config);
            })
            .WithName("Authorize")
            .WithTags("oidc")
            .Produces<Dictionary<string, object>>(StatusCodes.Status200OK);
        }

        // authorize for pkce with prompt endpoint**************************************************
        if (config.EnablePkce)
        {
            group.MapGet("/authorize-ui", (HttpRequest request, HttpContext ctx, AppConfig config) =>
            {
                var clientId = request.Query["client_id"].ToString();
                var redirectUri = request.Query["redirect_uri"].ToString();

                if (!AuthStore.IsRedirectUriValid(clientId, redirectUri))
                    return Results.BadRequest("Invalid flow");

                var jti = Utils.GenerateBase64EncodedRandomBytes(16);
                var qs = request.QueryString.HasValue ? request.QueryString.Value : "";

                AuthSessionStore.Insert(new AuthSessionDto
                {
                    Jti = jti,
                    QueryString = qs!,
                    CreatedAtUtc = DateTime.UtcNow,
                    ExpiresAtUtc = DateTime.UtcNow + TimeSpan.FromMinutes(5)
                });

                return Results.Redirect($"/login.html?jti={Uri.EscapeDataString(jti)}");
            })
            .WithName("AuthorizeUI")
            .WithTags("oidc")
            .Produces<Dictionary<string, object>>(StatusCodes.Status200OK);
        }

        // handle ui based pkce login endpoint******************************************************
        if (config.EnablePkce)
        {
            group.MapPost("/login-ui", (HttpContext ctx, AppConfig config, IFormCollection form) =>

                AuthService.HandleUiLogin(form, config, ctx)

            )
            .WithName("LoginUI")
            .WithTags("Oidc");
        }

        // get auth session endpoint****************************************************************
        if (config.EnablePkce)
        {
            group.MapGet("/auth_session/{jti}", (string jti) =>
            {
                var session = AuthSessionStore.Get(jti);

                return session is null
                    ? Results.NotFound()
                    : Results.Json(session, MicroauthdJsonContext.Default.AuthSessionDto);
            })
            .WithName("GetAuthSession")
            .WithTags("oidc");
        }

        // login for pkce endpoint******************************************************************
        if (config.EnablePkce)
        {
            group.MapPost("/login", async (HttpContext ctx, IAntiforgery antiforgery, AppConfig config) =>
            {
                var valid = await antiforgery.IsRequestValidAsync(ctx);
                if (!valid)
                    return Results.StatusCode(StatusCodes.Status400BadRequest);

                if (!ctx.Request.HasFormContentType)
                    return Results.BadRequest(new ErrorResponse(false, "Invalid content type"));

                var form = await ctx.Request.ReadFormAsync();
                var username = form["username"].ToString();
                var password = form["password"].ToString();
                var code = form["code"].ToString();
                var redirectUri = form["redirect_uri"].ToString();
                var scope = form["scope"];
                var nonce = form["nonce"];

                var result = AuthService.HandleUserLoginWithCode(username, password, code, redirectUri, config);
                return result.ToHttpResult();
            })
            .AllowAnonymous()
            .WithName("HandleUserLogin")
            .Produces<MessageResponse>(StatusCodes.Status200OK)
            .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
            .Produces<ErrorResponse>(StatusCodes.Status403Forbidden)
            .WithTags("Auth")
            .WithOpenApi();
        }
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

                "authorization_code" => AuthService.ExchangePkceCode(
                    form,
                    config)
                .ToHttpResult(),

                _ => ApiResult<TokenResponse>.Fail("Unsupported grant_type", 400).ToHttpResult()
            };            
        })
        .AllowAnonymous()
        .WithName("IssueToken")
        .Produces<TokenResponse>(StatusCodes.Status200OK)
        .Produces<OidcErrorResponse>(StatusCodes.Status400BadRequest)
        .Produces<OidcErrorResponse>(StatusCodes.Status403Forbidden)
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
                config: config
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
                if (config.EnableAuditLogging)
                    Utils.Audit.Logg(
                        action: "token.introspect.failure",
                        target: $"client={clientId} reason=missing_fields"
                    );

                return ApiResult<Dictionary<string, object>>
                    .Fail("Authorization Failed", 403)
                    .ToHttpResult();
            }

            var client = AuthService.AuthenticateClient(clientId, clientSecret, config);
            if (client is null)
            {
                if (config.EnableAuditLogging)
                    Utils.Audit.Logg(
                        action: "token.introspect.failure",
                        target: $"client={clientId} reason=invalid_client_credentials"
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
