using madTypes.Api.Requests;
using madTypes.Api.Responses;
using microauthd.Common;
using microauthd.Config;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

using Serilog;

using static nebulae.dotArgon2.Argon2;
using microauthd.Tokens;

namespace microauthd.Routes.Admin;

public static class AdminRoutes
{
    /// <summary>
    /// Configures and maps a set of administrative API routes to the provided <see cref="IEndpointRouteBuilder"/>.
    /// </summary>
    /// <remarks>This method defines a collection of endpoints for administrative operations, including user
    /// management, session management, role and permission management, and other administrative tasks. Each endpoint is
    /// configured with appropriate routes, HTTP methods, authorization requirements, and response types.  The routes
    /// include: - Informational endpoints (e.g., `/ping`, `/version`). - User management endpoints (e.g., create, list,
    /// update, delete users). - Session management endpoints (e.g., list, revoke sessions). - Role and permission
    /// management endpoints (e.g., assign roles, list permissions). - Client and scope management endpoints (e.g.,
    /// create clients, assign scopes).  All endpoints requiring sensitive operations are secured with
    /// authorization.</remarks>
    /// <param name="routes">The <see cref="IEndpointRouteBuilder"/> to which the administrative routes will be added.</param>
    /// <returns>A <see cref="RouteGroupBuilder"/> representing the group of administrative routes.</returns>
    public static RouteGroupBuilder MapAdminRoutes(this IEndpointRouteBuilder routes)
    {
        var group = routes.MapGroup("");

        // ping endpoint****************************************************************************
        group.MapGet("/ping", () =>
        {
            var ping = new PingResponse("pong from admin");
            return Results.Json(ping, MicroauthJsonContext.Default.PingResponse);

        }).WithTags("Info")
        .WithOpenApi();

        // version endpoint*************************************************************************
        group.MapGet("/version", () =>
        {
            var version = typeof(Program).Assembly.GetName().Version?.ToString() ?? "unknown";
            return Results.Ok(new { version });

        }).WithTags("Info")
        .WithOpenApi();

        // create user endpoint*********************************************************************
        group.MapPost("/users", (CreateUserRequest req, AppConfig config, HttpContext ctx) =>
        {
            var ip = ctx.Connection.RemoteIpAddress?.ToString();
            var ua = ctx.Request.Headers["User-Agent"].FirstOrDefault();
            var result = UserService.CreateUser(req.Username, req.Email, req.Password, config, ip, ua);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("CreateUser")
        .Produces<MessageResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .WithTags("Users")
        .WithOpenApi();

        // get users endpoint**********************************************************************
        group.MapGet("/users", () =>
        {
            var result = UserService.GetAllUsers();
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("ListUsers")
        .Produces<List<UserResponse>>(StatusCodes.Status200OK)
        .WithTags("Users")
        .WithOpenApi();

        // get user by ID endpoint******************************************************************
        group.MapGet("/users/{id}", (string id) =>
        {
            var result = UserService.GetUserById(id);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("GetUser")
        .Produces<UserResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status404NotFound)
        .WithTags("Users")
        .WithOpenApi();

        // soft-delete user endpoint****************************************************************
        group.MapDelete("/users/{id}", (string id, HttpContext ctx) =>
        {
            var ip = ctx.Connection.RemoteIpAddress?.ToString();
            var ua = ctx.Request.Headers["User-Agent"].FirstOrDefault();

            var result = UserService.SoftDeleteUser(id, ip, ua);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("DeleteUser")
        .Produces<MessageResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .WithTags("Users")
        .WithOpenApi();

        // reset user password endpoint*************************************************************
        group.MapPost("/users/{id}/reset", (string id, ResetPasswordRequest req, AppConfig config, HttpContext ctx) =>
        {
            var ip = ctx.Connection.RemoteIpAddress?.ToString();
            var ua = ctx.Request.Headers["User-Agent"].FirstOrDefault();

            var result = UserService.ResetUserPassword(id, req.NewPassword, config, ip, ua);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("ResetUserPassword")
        .Produces<MessageResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .WithTags("Users")
        .WithOpenApi();

        // activate a (soft) deleted user endpoint**************************************************
        group.MapPost("/users/{id}/activate", (string id, HttpContext ctx) =>
        {
            var ip = ctx.Connection.RemoteIpAddress?.ToString();
            var ua = ctx.Request.Headers["User-Agent"].FirstOrDefault();

            var result = UserService.ReactivateSoftDeletedUser(id, ip, ua);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("ActivateUser")
        .Produces<MessageResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .WithTags("Users")
        .WithOpenApi();

        // token request endpoint*******************************************************************
        group.MapPost("/token", (TokenRequest req, AppConfig config, HttpContext ctx) =>
        {
            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var ua = ctx.Request.Headers["User-Agent"].FirstOrDefault() ?? "unknown";

            var result = AuthService.IssueAdminToken(req, config, ip, ua);
            return result.ToHttpResult();
        })
        .WithName("IssueToken")
        .Produces<TokenResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status403Forbidden)
        .WithTags("Authentication")
        .WithOpenApi();

        // get sessions endpoint*******************************************************************
        group.MapGet("/sessions", () =>
        {
            var result = UserService.GetAllSessions();
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("ListSessions")
        .Produces<List<SessionResponse>>(StatusCodes.Status200OK)
        .WithTags("Sessions")
        .WithOpenApi();

        // get detail for a single session endpoint*************************************************
        group.MapGet("/sessions/{jti}", (string jti) =>
        {
            var result = UserService.GetSessionById(jti);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("GetSession")
        .Produces<SessionResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status404NotFound)
        .WithTags("Sessions")
        .WithOpenApi();

        // delete session endpoint******************************************************************
        group.MapDelete("/sessions/{jti}", (string jti, HttpContext ctx) =>
        {
            var ip = ctx.Connection.RemoteIpAddress?.ToString();
            var ua = ctx.Request.Headers["User-Agent"].FirstOrDefault();

            var result = UserService.RevokeSessionById(jti, ip, ua);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("RevokeSession")
        .Produces(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status404NotFound)
        .WithTags("Sessions")
        .WithOpenApi();

        // get sessions by user endpoint************************************************************
        group.MapGet("/sessions/user/{userId}", (string userId) =>
        {
            var result = UserService.GetSessionsByUserId(userId);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("GetSessionsByUser")
        .Produces<List<SessionResponse>>(StatusCodes.Status200OK)
        .WithTags("Sessions")
        .WithOpenApi();

        // revoke session endpoint******************************************************************
        group.MapPost("/revoke", ([FromBody] string jti, HttpContext ctx) =>
        {
            var ip = ctx.Connection.RemoteIpAddress?.ToString();
            var ua = ctx.Request.Headers["User-Agent"].FirstOrDefault();

            var result = UserService.RevokeSessionById(jti, ip, ua);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("RevokeToken")
        .Produces(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .WithTags("Sessions")
        .WithOpenApi();

        // get refresh tokens endpoint**************************************************************
        group.MapGet("/refresh-tokens", () =>
        {
            var result = UserService.GetAllRefreshTokens();
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("ListRefreshTokens")
        .Produces<List<RefreshTokenResponse>>(StatusCodes.Status200OK)
        .WithTags("Refresh Tokens")
        .WithOpenApi();

        // get refresh token by ID endpoint*********************************************************
        group.MapGet("/refresh-tokens/{id}", (string id) =>
        {
            var result = UserService.GetRefreshTokenById(id);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("GetRefreshToken")
        .Produces<RefreshTokenResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status404NotFound)
        .WithTags("Refresh Tokens")
        .WithOpenApi();

        // get refresh tokens by user ID endpoint***************************************************
        group.MapGet("/refresh-tokens/user/{userId}", (string userId) =>
        {
            var result = UserService.GetRefreshTokensByUserId(userId);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("GetRefreshTokensByUser")
        .Produces<List<RefreshTokenResponse>>(StatusCodes.Status200OK)
        .WithTags("Refresh Tokens")
        .WithTags("Users")
        .WithOpenApi();

        // purge expired sessions endpoint**********************************************************
        group.MapPost("/sessions/purge", (PurgeTokensRequest req, HttpContext ctx) =>
        {
            var ip = ctx.Connection.RemoteIpAddress?.ToString();
            var ua = ctx.Request.Headers["User-Agent"].FirstOrDefault();
            var userId = ctx.User.Claims.FirstOrDefault(c => c.Type == "sub")?.Value;

            var span = TimeSpan.FromSeconds(req.OlderThanSeconds);
            var result = UserService.PurgeSessions(span, req.PurgeExpired, req.PurgeRevoked, userId, ip, ua);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("PurgeSessions")
        .Produces<MessageResponse>(StatusCodes.Status200OK)
        .WithTags("Sessions")
        .WithOpenApi();

        // purge refresh tokens endpoint************************************************************
        group.MapPost("/refresh-tokens/purge", (PurgeTokensRequest req, HttpContext ctx) =>
        {
            var ip = ctx.Connection.RemoteIpAddress?.ToString();
            var ua = ctx.Request.Headers["User-Agent"].FirstOrDefault();
            var userId = ctx.User.Claims.FirstOrDefault(c => c.Type == "sub")?.Value;

            var result = UserService.PurgeRefreshTokens(req, userId, ip, ua);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("PurgeRefreshTokens")
        .Produces<MessageResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .WithTags("Refresh Tokens")
        .WithOpenApi();

        // create role endpoint*********************************************************************
        group.MapPost("/roles", (CreateRoleRequest req, HttpContext ctx) =>
        {
            var ip = ctx.Connection.RemoteIpAddress?.ToString();
            var ua = ctx.Request.Headers["User-Agent"].FirstOrDefault();
            var userId = ctx.User.Claims.FirstOrDefault(c => c.Type == "sub")?.Value;

            var result = RoleService.CreateRole(req.Name, req.Description, userId, ip, ua);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("CreateRole")
        .Produces<MessageResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .WithTags("Roles")
        .WithOpenApi();

        // list roles endpoint**********************************************************************
        group.MapGet("/roles", () =>
        {
            var result = RoleService.ListAllRoles();
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("ListRoles")
        .Produces<List<RoleResponse>>(StatusCodes.Status200OK)
        .WithTags("Roles")
        .WithOpenApi();

        // delete role endpoint*********************************************************************
        group.MapDelete("/roles/{roleId}", (string roleId, HttpContext ctx) =>
        {
            var ip = ctx.Connection.RemoteIpAddress?.ToString();
            var ua = ctx.Request.Headers["User-Agent"].FirstOrDefault();
            var userId = ctx.User.Claims.FirstOrDefault(c => c.Type == "sub")?.Value;

            var result = RoleService.SoftDeleteRole(roleId, userId, ip, ua);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("DeleteRole")
        .Produces<MessageResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .WithTags("Roles")
        .WithOpenApi();

        // assign roles endpoint********************************************************************
        group.MapPost("/roles/assign", (AssignRoleRequest req, AppConfig config, HttpContext ctx) =>
        {
            var userId = ctx.User.Claims.FirstOrDefault(c => c.Type == "sub")?.Value;
            var ip = ctx.Connection.RemoteIpAddress?.ToString();
            var ua = ctx.Request.Headers["User-Agent"].FirstOrDefault();

            var result = RoleService.AddRoleToUser(req.UserId, req.RoleId, config, userId, ip, ua);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("AssignRoleToUser")
        .Produces<MessageResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .WithTags("Roles")
        .WithOpenApi();

        // unassign roles endpoint******************************************************************
        group.MapPost("/roles/unassign", (AssignRoleRequest req, AppConfig config, HttpContext ctx) =>
        {
            var actor = ctx.User.Claims.FirstOrDefault(c => c.Type == "sub")?.Value;
            var ip = ctx.Connection.RemoteIpAddress?.ToString();
            var ua = ctx.Request.Headers["User-Agent"].FirstOrDefault();

            var result = RoleService.RemoveRoleFromUser(req.UserId, req.RoleId, config, actor, ip, ua);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("UnassignRoleFromUser")
        .Produces<MessageResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .WithTags("Roles")
        .WithTags("Users")
        .WithOpenApi();

        // list roles for user endpoint*************************************************************
        group.MapGet("/roles/user/{userId}", (string userId) =>
        {
            var result = RoleService.ListRolesForUser(userId);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("ListRolesForUser")
        .Produces<List<string>>(StatusCodes.Status200OK)
        .WithTags("Roles")
        .WithTags("Users")
        .WithOpenApi();

        // create permission endpoint***************************************************************
        group.MapPost("/permissions", (
            CreatePermissionRequest req,
            ClaimsPrincipal user,
            HttpContext ctx) =>
        {
            var userId = user.FindFirst("sub")?.Value;
            var ip = ctx.Connection.RemoteIpAddress?.ToString();
            var ua = ctx.Request.Headers.UserAgent.ToString();

            var result = RoleService.CreatePermission(req.Name, userId, ip, ua);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("CreatePermission")
        .Produces<MessageResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .WithTags("Permissions")
        .WithOpenApi();

        // list permissions endpoint****************************************************************
        group.MapGet("/permissions", () =>
        {
            var result = RoleService.ListAllPermissions();
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("ListPermissions")
        .Produces<List<PermissionResponse>>(StatusCodes.Status200OK)
        .WithTags("Permissions")
        .WithOpenApi();

        // delete permission by ID endpoint*********************************************************
        group.MapDelete("/permissions/{permissionId}", (string permissionId, HttpContext context) =>
        {
            var result = RoleService.SoftDeletePermission(
                permissionId,
                context.User.GetUserId(),
                context.Connection.RemoteIpAddress?.ToString(),
                context.Request.Headers.UserAgent.ToString()
            );
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("DeletePermission")
        .Produces<MessageResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .WithTags("Permissions")
        .WithOpenApi();

        // assign permission to role endpoint*******************************************************
        group.MapPost("/roles/{roleId}/permissions", (string roleId, AssignPermissionRequest req, HttpContext ctx) =>
        {
            var result = RoleService.AssignPermissionsToRole(
                roleId,
                req.PermissionIds,
                ctx.User.GetUserId(),
                ctx.Connection.RemoteIpAddress?.ToString(),
                ctx.Request.Headers.UserAgent.ToString()
            );
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("AssignPermissionsToRole")
        .Produces<MessageResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .WithTags("Permissions")
        .WithTags("Roles")
        .WithOpenApi();

        // remove permission from role endpoint*****************************************************
        group.MapDelete("/roles/{roleId}/permissions/{permissionId}", (string roleId, string permissionId, HttpContext ctx) =>
        {
            var result = RoleService.RemovePermissionFromRole(
                roleId,
                permissionId,
                ctx.User.GetUserId(),
                ctx.Connection.RemoteIpAddress?.ToString(),
                ctx.Request.Headers.UserAgent.ToString()
            );
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("RemovePermissionFromRole")
        .Produces<MessageResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .WithTags("Permissions")
        .WithTags("Roles")
        .WithOpenApi();

        // get effective permissions for user endpoint**********************************************
        group.MapGet("/permissions/user/{userId}", (string userId) =>
        {
            var result = RoleService.GetEffectivePermissionsForUser(userId);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("GetPermissionsForUser")
        .Produces<List<string>>(StatusCodes.Status200OK)
        .WithTags("Permissions")
        .WithTags("Users")
        .WithOpenApi();

        // check access endpoint********************************************************************
        group.MapPost("/check-access", (CheckAccessRequest req) =>
        {
            var result = RoleService.UserHasPermission(req.UserId, req.PermissionId);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("CheckAccess")
        .Produces(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .WithTags("Permissions")
        .WithOpenApi();

        // create client endpoint*******************************************************************
        group.MapPost("/clients", (
            CreateClientRequest req,
            AppConfig config,
            HttpContext ctx
        ) =>
        {
            var result = RoleService.TryCreateClient(
                req,
                config,
                ctx.User.GetUserId(),
                ctx.Connection.RemoteIpAddress?.ToString(),
                ctx.Request.Headers.UserAgent.ToString()
            );
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("CreateClient")
        .Produces<MessageResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .WithTags("Clients")
        .WithOpenApi();

        // get permissions for role endpoint********************************************************
        group.MapGet("/roles/{roleId}/permissions", (string roleId) =>
        {
            var result = RoleService.GetPermissionsForRole(roleId);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("GetPermissionsForRole")
        .Produces<List<string>>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .WithTags("Permissions")
        .WithTags("Roles")
        .WithOpenApi();

        // list scopes endpoint*********************************************************************
        group.MapGet("/scopes", () =>
        {
            var result = RoleService.ListAllScopes();
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("ListScopes")
        .Produces<List<ScopeResponse>>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .WithTags("Scopes")
        .WithOpenApi();

        // create scope endpoint********************************************************************
        group.MapPost("/scopes", (
            ScopeResponse req,
            HttpContext ctx
        ) =>
        {
            var result = RoleService.CreateScope(
                req,
                ctx.User.GetUserId(),
                ctx.Connection.RemoteIpAddress?.ToString(),
                ctx.Request.Headers.UserAgent.ToString()
            );
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("CreateScope")
        .Produces<MessageResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .WithTags("Scopes")
        .WithOpenApi();

        // delete scope endpoint********************************************************************
        group.MapDelete("/scopes/{scopeId}", (
            string scopeId,
            HttpContext ctx
        ) =>
        {
            var result = RoleService.SoftDeleteScope(
                scopeId,
                ctx.User.GetUserId(),
                ctx.Connection.RemoteIpAddress?.ToString(),
                ctx.Request.Headers.UserAgent.ToString()
            );
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("DeleteScope")
        .Produces<MessageResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .WithTags("Scopes")
        .WithOpenApi();

        // get clients endpoint********************************************************************
        group.MapGet("/clients", () =>
        {
            var result = RoleService.GetAllClients();
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("ListClients")
        .Produces<List<ClientResponse>>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .WithTags("Clients")
        .WithOpenApi();

        // delete client endpoint*******************************************************************
        group.MapDelete("/clients/{id}", (
            string id,
            HttpContext ctx
        ) =>
        {
            var result = RoleService.SoftDeleteClient(
                id,
                ctx.User.GetUserId(),
                ctx.Connection.RemoteIpAddress?.ToString(),
                ctx.Request.Headers.UserAgent.ToString()
            );
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("DeleteClient")
        .Produces<MessageResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .WithTags("Clients")
        .WithOpenApi();

        // add scopes to client endpoint************************************************************
        group.MapPost("/clients/{clientId}/scopes", (
            string clientId,
            AssignScopesRequest req,
            HttpContext ctx
        ) =>
        {
            var result = RoleService.AddScopesToClient(
                clientId,
                req,
                ctx.User.GetUserId(),
                ctx.Connection.RemoteIpAddress?.ToString(),
                ctx.Request.Headers.UserAgent.ToString()
            );
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("AssignScopesToClient")
        .Produces<MessageResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .WithTags("Clients")
        .WithOpenApi();

        // get scopes for client endpoint**********************************************************
        group.MapGet("/clients/{id}/scopes", (string id) =>
        {
            var result = RoleService.GetScopesForClient(id);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("ListClientScopes")
        .Produces<List<ScopeResponse>>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .WithTags("Clients")
        .WithTags("Scopes")
        .WithOpenApi();

        // remove scope from client endpoint********************************************************
        group.MapDelete("/clients/{id}/scopes/{scopeId}", (
            string id,
            string scopeId,
            HttpContext ctx
        ) =>
        {
            var result = RoleService.RemoveScopeFromClient(
                id,
                scopeId,
                ctx.User.GetUserId(),
                ctx.Connection.RemoteIpAddress?.ToString(),
                ctx.Request.Headers.UserAgent.ToString()
            );

            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("RemoveScopeFromClient")
        .Produces<MessageResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .WithTags("Clients")
        .WithTags("Scopes")
        .WithOpenApi();

        // List scopes for a user endpoint**********************************************************
        group.MapGet("/users/{userId}/scopes", (string userId) =>
        {
            var result = RoleService.ListScopesForUser(userId);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("ListUserScopes")
        .Produces<List<ScopeResponse>>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .WithOpenApi();

        // assign scopes to a user endpoint*********************************************************
        group.MapPost("/users/{userId}/scopes", (
            string userId,
            AssignScopesRequest req,
            HttpContext ctx
        ) =>
        {
            var result = RoleService.AddScopesToUser(
                userId,
                req,
                ctx.User.GetUserId(),
                ctx.Connection.RemoteIpAddress?.ToString(),
                ctx.Request.Headers.UserAgent.ToString()
            );

            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("AssignScopesToUser")
        .Produces<MessageResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .WithOpenApi();

        // remove scope from user endpoing**********************************************************
        group.MapDelete("/users/{userId}/scopes/{scopeId}", (
            string userId,
            string scopeId,
            HttpContext ctx
        ) =>
        {
            var result = RoleService.RemoveScopeFromUser(
                userId,
                scopeId,
                ctx.User.GetUserId(),
                ctx.Connection.RemoteIpAddress?.ToString(),
                ctx.Request.Headers.UserAgent.ToString()
            );

            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("RemoveUserScope")
        .Produces<MessageResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .WithOpenApi();

        // get audit logs endpoing******************************************************************
        group.MapGet("/audit-logs", (
            [FromQuery] string? userId,
            [FromQuery] string? action,
            [FromQuery] int? limit
        ) =>
        {
            return AuditService
                .GetAuditLogs(userId, action, limit ?? 100)
                .ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("ListAuditLogs")
        .Produces<List<AuditLogResponse>>(StatusCodes.Status200OK)
        .WithTags("Audit")
        .WithOpenApi();

        // get audit log by ID endpoint*************************************************************
        group.MapGet("/audit-logs/{id}", (string id) =>
        {
            return AuditService
                .GetAuditLogById(id)
                .ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("GetAuditLogById")
        .Produces<AuditLogResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status404NotFound)
        .WithTags("Audit")
        .WithOpenApi();

        // purge audit logs endpoint****************************************************************
        group.MapPost("/audit-logs/purge", (PurgeAuditLogRequest req) =>
        {
            if (req.OlderThanDays <= 0)
                return ApiResult<MessageResponse>
                    .Fail("olderThanDays must be greater than 0")
                    .ToHttpResult();

            return AuditService
                .PurgeLogsOlderThan(TimeSpan.FromDays(req.OlderThanDays))
                .ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("PurgeAuditLogs")
        .Produces<MessageResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .WithTags("Audit")
        .WithOpenApi();

        return group;
    }
}