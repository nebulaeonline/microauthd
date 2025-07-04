﻿using madTypes.Api.Requests;
using madTypes.Api.Responses;
using madTypes.Common;
using microauthd.Common;
using microauthd.Config;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

using Serilog;

using static nebulae.dotArgon2.Argon2;
using microauthd.Tokens;
using madTypes.Api.Common;
using microauthd.Services;
using microauthd.Data;

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
    public static RouteGroupBuilder MapAdminRoutes(this IEndpointRouteBuilder routes, AppConfig config)
    {
        var group = routes.MapGroup("");

        // ping endpoint****************************************************************************
        group.MapGet("/ping", () =>
        {
            var ping = new PingResponse("pong from admin");
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
        .Produces<VersionResponse>(StatusCodes.Status200OK)
        .WithOpenApi();

        // create user endpoint*********************************************************************
        group.MapPost("/users", (CreateUserRequest req, AppConfig config) =>
        {
            var result = UserService.CreateUser(req.Username, req.Email, req.Password, config);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("CreateUser")
        .Produces<UserObject>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .WithTags("Users")
        .WithOpenApi();

        // get users endpoint**********************************************************************
        group.MapGet("/users", () =>
        {
            var result = UserService.ListUsers();
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("ListUsers")
        .Produces<List<UserObject>>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
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
        .Produces<UserObject>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status404NotFound)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithTags("Users")
        .WithOpenApi();

        // get user id by username endpoint*********************************************************
        group.MapGet("/users/id-by-name/{username}", (string username) =>
        {
            return UserService.GetUserIdByUsername(username).ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("GetUserIdByUsername")
        .Produces<ApiResult<string>>(StatusCodes.Status200OK)
        .Produces<ApiResult<ErrorResponse>>(StatusCodes.Status404NotFound)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithTags("Users")
        .WithOpenApi();

        // update user endpoint*********************************************************************
        group.MapPut("/users/{id}", (
            string id,
            UserObject updated,
            AppConfig config,
            HttpContext ctx
        ) =>
        {
            var result = UserService.UpdateUser(id, updated, config);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("UpdateUser")
        .Produces<UserObject>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithTags("Users")
        .WithOpenApi();

        // mark user's email as verified endpoint***************************************************
        group.MapPost("/users/{id}/verify-email", (string id) =>
            UserService.MarkEmailVerified(id).ToHttpResult()
        )
        .RequireAuthorization()
        .WithName("VerifyEmail")
        .Produces<ApiResult<string>>(StatusCodes.Status200OK)
        .Produces<ApiResult<ErrorResponse>>(StatusCodes.Status404NotFound)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithTags("Users");

        // soft-delete user endpoint****************************************************************
        group.MapPost("/users/deactivate/{id}", (string id, AppConfig config) =>
        {
            var result = UserService.DeactivateUser(id, config);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("DeactivateUser")
        .Produces<MessageResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithTags("Users")
        .WithOpenApi();

        // delete user permanently endpoint*********************************************************
        group.MapDelete("/users/{id}", (string id, AppConfig config, ClaimsPrincipal user) =>
        {
            return UserService.DeleteUser(id, config).ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("DeleteUser")
        .Produces<MessageResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status404NotFound)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithTags("Users")
        .WithOpenApi();


        // reset user password endpoint*************************************************************
        group.MapPost("/users/{id}/reset", (string id, ResetPasswordRequest req, AppConfig config) =>
        {
            var result = UserService.ResetUserPassword(id, req.NewPassword, config);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("ResetUserPassword")
        .Produces<MessageResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithTags("Users")
        .WithOpenApi();

        // activate a (soft) deleted user endpoint**************************************************
        group.MapPost("/users/{id}/activate", (string id, AppConfig config) =>
        {
            var result = UserService.ReactivateUser(id, config);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("ActivateUser")
        .Produces<MessageResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithTags("Users")
        .WithOpenApi();

        // set user lockout endpoint****************************************************************
        group.MapPost("/users/{id}/set-lockout", (string id, SetUserLockoutRequest req, AppConfig config) =>
        {
            var result = UserService.SetLockout(id, req.LockoutUntil, config);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("SetUserLockout")
        .Produces<MessageResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithTags("Users")
        .WithOpenApi();

        // token request endpoint*******************************************************************
        group.MapPost("/token", async (AppConfig config, HttpContext ctx) =>
        {
            if (!ctx.Request.HasFormContentType)
                return ApiResult<TokenResponse>
                    .Fail("Invalid credentials", 400)
                    .ToHttpResult();

            var form = await ctx.Request.ReadFormAsync();

            var req = new TokenRequest
            {
                Username = form["username"],
                Password = form["password"],
                ClientIdentifier = form["client_id"]
            };

            if (string.IsNullOrWhiteSpace(req.Username) ||
                string.IsNullOrWhiteSpace(req.Password) ||
                string.IsNullOrWhiteSpace(req.ClientIdentifier))
            {
                return ApiResult<TokenResponse>
                    .Fail("Invalid credentials", 400)
                    .ToHttpResult();
            }

            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var ua = ctx.Request.Headers["User-Agent"].FirstOrDefault() ?? "unknown";

            var result = AuthService.IssueAdminToken(req, config, ip, ua);
            return result.ToHttpResult();
        })
        .AllowAnonymous()
        .WithName("IssueToken")
        .Produces<TokenResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status403Forbidden)
        .WithTags("Authentication")
        .WithOpenApi();

        // get sessions endpoint*******************************************************************
        group.MapGet("/sessions", () =>
        {
            var result = UserService.ListSessions();
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("ListSessions")
        .Produces<List<SessionResponse>>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
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
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithTags("Sessions")
        .WithOpenApi();

        // delete session endpoint******************************************************************
        if (config.EnableTokenRevocation)
        {
            group.MapDelete("/sessions/{jti}", (string jti, AppConfig config) =>
            {
                var result = UserService.RevokeSessionById(jti, config);
                return result.ToHttpResult();
            })
            .RequireAuthorization()
            .WithName("RevokeSession")
            .Produces(StatusCodes.Status200OK)
            .Produces<ErrorResponse>(StatusCodes.Status404NotFound)
            .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
            .WithTags("Sessions")
            .WithOpenApi();
        }
        // get sessions by user endpoint************************************************************
        group.MapGet("/sessions/user/{userId}", (string userId) =>
        {
            var result = UserService.GetSessionsByUserId(userId);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("GetSessionsByUser")
        .Produces<List<SessionResponse>>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithTags("Sessions")
        .WithOpenApi();

        // revoke session endpoint******************************************************************
        if (config.EnableTokenRevocation)
        {
            group.MapPost("/revoke", async (HttpContext ctx) =>
            {
                var form = await ctx.Request.ReadFormAsync();
                var token = form["token"].ToString();

                if (string.IsNullOrWhiteSpace(token))
                {
                    return ApiResult<MessageResponse>.Fail("Missing token").ToHttpResult();
                }

                var result = AuthService.RevokeToken(token);
                return result.ToHttpResult();
            })
            .RequireAuthorization()
            .WithName("RevokeToken")
            .Produces<MessageResponse>(StatusCodes.Status200OK)
            .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
            .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
            .WithTags("Tokens")
            .Accepts<IFormCollection>("application/x-www-form-urlencoded")
            .WithOpenApi();
        }

        // get refresh tokens endpoint**************************************************************
        if (config.EnableTokenRefresh)
        {
            group.MapGet("/refresh-tokens", () =>
            {
                var result = UserService.ListRefreshTokens();
                return result.ToHttpResult();
            })
            .RequireAuthorization()
            .WithName("ListRefreshTokens")
            .Produces<List<RefreshTokenResponse>>(StatusCodes.Status200OK)
            .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
            .WithTags("Refresh Tokens")
            .WithOpenApi();
        }

        // get refresh token by ID endpoint*********************************************************
        if (config.EnableTokenRefresh)
        {
            group.MapGet("/refresh-tokens/{id}", (string id) =>
            {
                var result = UserService.GetRefreshTokenById(id);
                return result.ToHttpResult();
            })
            .RequireAuthorization()
            .WithName("GetRefreshToken")
            .Produces<RefreshTokenResponse>(StatusCodes.Status200OK)
            .Produces<ErrorResponse>(StatusCodes.Status404NotFound)
            .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
            .WithTags("Refresh Tokens")
            .WithOpenApi();
        }

        // get refresh tokens by user ID endpoint***************************************************
        if (config.EnableTokenRefresh)
        {
            group.MapGet("/refresh-tokens/user/{userId}", (string userId) =>
            {
                var result = UserService.GetRefreshTokensByUserId(userId);
                return result.ToHttpResult();
            })
            .RequireAuthorization()
            .WithName("GetRefreshTokensByUser")
            .Produces<List<RefreshTokenResponse>>(StatusCodes.Status200OK)
            .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
            .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
            .WithTags("Refresh Tokens")
            .WithTags("Users")
            .WithOpenApi();
        }

        // purge expired sessions endpoint**********************************************************
        group.MapPost("/sessions/purge", (PurgeTokensRequest req, AppConfig config) =>
        {
            var span = TimeSpan.FromSeconds(req.OlderThanSeconds);
            var cutoffUtc = DateTime.UtcNow - span;
            var result = UserService.PurgeSessions(cutoffUtc, req.PurgeExpired, req.PurgeRevoked, config);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("PurgeSessions")
        .Produces<MessageResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithTags("Sessions")
        .WithOpenApi();

        // purge refresh tokens endpoint************************************************************
        if (config.EnableTokenRefresh)
        {
            group.MapPost("/refresh-tokens/purge", (PurgeTokensRequest req, AppConfig config) =>
            {
                var result = UserService.PurgeRefreshTokens(req, config);
                return result.ToHttpResult();
            })
            .RequireAuthorization()
            .WithName("PurgeRefreshTokens")
            .Produces<MessageResponse>(StatusCodes.Status200OK)
            .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
            .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
            .WithTags("Refresh Tokens")
            .WithOpenApi();
        }

        // create role endpoint*********************************************************************
        group.MapPost("/roles", (CreateRoleRequest req, AppConfig config) =>
        {
            var result = RoleService.CreateRole(req.Name, req.Description, config);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("CreateRole")
        .Produces<RoleObject>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithTags("Roles")
        .WithOpenApi();

        // update role endpoint*********************************************************************
        group.MapPut("/roles/{id}", (
            string id,
            RoleObject updated,
            AppConfig config
        ) =>
        {
            var result = RoleService.UpdateRole(id, updated, config);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("UpdateRole")
        .Produces<RoleObject>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
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
        .Produces<List<RoleObject>>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithTags("Roles")
        .WithOpenApi();

        // get role by id endpoint************************************************************************
        group.MapGet("/roles/{id}", (
            string id,
            AppConfig config
        ) =>
        {
            var result = RoleService.GetRoleById(id);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("GetRoleById")
        .Produces<RoleObject>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status404NotFound)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithTags("Roles")
        .WithOpenApi();

        // get role id by name endpoint*************************************************************
        group.MapGet("/roles/id-by-name/{name}", (string name) =>
        {
            return RoleService.GetRoleIdByName(name).ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("GetRoleIdByName")
        .Produces<ApiResult<string>>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .Produces<ApiResult<ErrorResponse>>(StatusCodes.Status404NotFound)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithTags("Roles")
        .WithOpenApi();

        // delete role endpoint*********************************************************************
        group.MapDelete("/roles/{roleId}", (string roleId, AppConfig config) =>
        {
            var result = RoleService.DeleteRole(roleId, config);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("DeleteRole")
        .Produces<MessageResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithTags("Roles")
        .WithOpenApi();

        // assign roles endpoint********************************************************************
        group.MapPost("/roles/assign", (AssignRoleRequest req, AppConfig config) =>
        {
            var result = RoleService.AddRoleToUser(req.UserId, req.RoleId, config);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("AssignRoleToUser")
        .Produces<MessageResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithTags("Roles")
        .WithOpenApi();

        // unassign roles endpoint******************************************************************
        group.MapPost("/roles/unassign", (AssignRoleRequest req, AppConfig config) =>
        {
            var result = RoleService.RemoveRoleFromUser(req.UserId, req.RoleId, config);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("UnassignRoleFromUser")
        .Produces<MessageResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
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
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithTags("Roles")
        .WithTags("Users")
        .WithOpenApi();

        // get role DTOs for all / user endpoint****************************************************
        group.MapGet("/users/{userId}/roles", (
            string userId,
            [FromQuery] bool all
        ) =>
        {
            var roles = all
                ? RoleService.GetAllRoleDtos()
                : RoleService.GetAssignedRoleDtos(userId);

            return roles.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("GetUserRoles")
        .Produces<ApiResult<List<RoleDto>>>(StatusCodes.Status200OK)
        .Produces<ApiResult<ErrorResponse>>(StatusCodes.Status404NotFound)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithTags("Users")
        .WithTags("Roles")
        .WithOpenApi();

        // replace user roles endpoint**************************************************************
        group.MapPut("/users/{userId}/roles", (
            string userId,
            [FromBody] List<RoleDto> roles,
            AppConfig config
        ) =>
        {
            var roleAssignment = new RoleAssignmentDto
            {
                UserId = userId,
                Roles = roles
            };

            var result = RoleService.ReplaceUserRoles(roleAssignment, config);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("ReplaceUserRoles")
        .Produces<ApiResult<MessageResponse>>(StatusCodes.Status200OK)
        .Produces<ApiResult<ErrorResponse>>(StatusCodes.Status400BadRequest)
        .WithTags("Users")
        .WithTags("Roles")
        .WithOpenApi();

        // create permission endpoint***************************************************************
        group.MapPost("/permissions", (
            CreatePermissionRequest req,
            ClaimsPrincipal user,
            AppConfig config) =>
        {
            var result = PermissionService.CreatePermission(req.Name, config);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("CreatePermission")
        .Produces<PermissionObject>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithTags("Permissions")
        .WithOpenApi();

        // update permission endpoint***************************************************************
        group.MapPut("/permissions/{id}", (
            string id,
            PermissionObject updated,
            AppConfig config
        ) =>
        {
            var result = PermissionService.UpdatePermission(id, updated, config);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("UpdatePermission")
        .Produces<PermissionObject>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithTags("Permissions")
        .WithOpenApi();

        // list permissions endpoint****************************************************************
        group.MapGet("/permissions", () =>
        {
            var result = PermissionService.ListAllPermissions();
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("ListPermissions")
        .Produces<List<PermissionObject>>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithTags("Permissions")
        .WithOpenApi();

        // get permission endpoint******************************************************************
        group.MapGet("/permissions/{id}", (string id, AppConfig config) =>
        {
            var result = PermissionService.GetPermissionById(id);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("GetPermissionById")
        .Produces<PermissionObject>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status404NotFound)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithTags("Permissions")
        .WithOpenApi();

        // get permission id by name endpoint*******************************************************
        group.MapGet("/permissions/id-by-name/{name}", (string name) =>
        {
            return PermissionService.GetPermissionIdByName(name).ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("GetPermissionIdByName")
        .Produces<ApiResult<string>>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .Produces<ApiResult<ErrorResponse>>(StatusCodes.Status404NotFound)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithTags("Permissions")
        .WithOpenApi();

        // delete permission by ID endpoint*********************************************************
        group.MapDelete("/permissions/{permissionId}", (string permissionId, AppConfig config) =>
        {
            var result = PermissionService.DeletePermission(
                permissionId,
                config
            );
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("DeletePermission")
        .Produces<MessageResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithTags("Permissions")
        .WithOpenApi();

        // get all permission DTOs endpoint*********************************************************
        group.MapGet("/permissions/retrieve/all", () =>
        {
            var result = PermissionService.GetAllPermissionDtos();
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("GetAllPermissionDtos")
        .Produces<List<PermissionDto>>(StatusCodes.Status200OK)
        .WithTags("Permissions")
        .WithOpenApi();

        // get permission DTOs for role endpoint****************************************************
        group.MapGet("/permissions/retrieve/{roleId}", (string roleId) =>
        {
            var result = PermissionService.GetAssignedPermissionDtos(roleId);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("GetAssignedPermissionDtos")
        .Produces<List<PermissionDto>>(StatusCodes.Status200OK)
        .WithTags("Permissions")
        .WithOpenApi();

        // assign permission to role endpoint*******************************************************
        group.MapPost("/roles/{roleId}/permissions", (
            string roleId, 
            AssignPermissionRequest req, 
            AppConfig config) =>
        {
            var result = PermissionService.AssignPermissionsToRole(
                roleId,
                req.PermissionId,
                config
            );
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("AssignPermissionsToRole")
        .Produces<MessageResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithTags("Permissions")
        .WithTags("Roles")
        .WithOpenApi();

        // remove permission from role endpoint*****************************************************
        group.MapDelete("/roles/{roleId}/permissions/{permissionId}", (
            string roleId, 
            string permissionId, 
            AppConfig config) =>
        {
            var result = PermissionService.RemovePermissionFromRole(
                roleId,
                permissionId,
                config
            );
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("RemovePermissionFromRole")
        .Produces<MessageResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithTags("Permissions")
        .WithTags("Roles")
        .WithOpenApi();

        // get effective permissions for user endpoint**********************************************
        group.MapGet("/permissions/user/{userId}", (string userId) =>
        {
            var result = PermissionService.GetEffectivePermissionsForUser(userId);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("GetPermissionsForUser")
        .Produces<List<PermissionObject>>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithTags("Permissions")
        .WithTags("Users")
        .WithOpenApi();

        // check access endpoint********************************************************************
        group.MapPost("/check-access", (CheckAccessRequest req) =>
        {
            var result = PermissionService.UserHasPermission(req.UserId, req.PermissionId);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("CheckAccess")
        .Produces(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithTags("Permissions")
        .WithOpenApi();

        // get permissions for role endpoint********************************************************
        group.MapGet("/roles/{roleId}/permissions", (string roleId) =>
        {
            var result = PermissionService.GetPermissionsForRole(roleId);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("GetPermissionsForRole")
        .Produces<List<PermissionObject>>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithTags("Permissions")
        .WithTags("Roles")
        .WithOpenApi();

        // create scope endpoint********************************************************************
        group.MapPost("/scopes", (
            ScopeObject req,
            AppConfig config
        ) =>
        {
            var result = ScopeService.CreateScope(
                req,
                config
            );
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("CreateScope")
        .Produces<ScopeObject>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithTags("Scopes")
        .WithOpenApi();

        // update scope endpoint********************************************************************
        group.MapPut("/scopes/{id}", (
            string id,
            ScopeObject updated,
            AppConfig config
        ) =>
        {
            var result = ScopeService.UpdateScope(id, updated, config);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("UpdateScope")
        .Produces<ScopeObject>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithTags("Scopes")
        .WithOpenApi();

        // list scopes endpoint*********************************************************************
        group.MapGet("/scopes", () =>
        {
            var result = ScopeService.ListAllScopes();
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("ListScopes")
        .Produces<List<ScopeObject>>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithTags("Scopes")
        .WithOpenApi();

        // get scope endpoint***********************************************************************
        group.MapGet("/scopes/{id}", (string id) =>
        {
            var result = ScopeService.GetScopeById(id);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("GetScopeById")
        .Produces<ScopeObject>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status404NotFound)
        .WithTags("Scopes")
        .WithOpenApi();

        // get scope id by name endpoint************************************************************
        group.MapGet("/scopes/id-by-name/{name}", (string name) =>
        {
            return ScopeService.GetScopeIdByName(name).ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("GetScopeIdByName")
        .Produces<ApiResult<string>>(StatusCodes.Status200OK)
        .Produces<ApiResult<ErrorResponse>>(StatusCodes.Status404NotFound)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithTags("Scopes")
        .WithOpenApi();

        // delete scope endpoint********************************************************************
        group.MapDelete("/scopes/{scopeId}", (
            string scopeId,
            AppConfig config
        ) =>
        {
            var result = ScopeService.DeleteScope(
                scopeId,
                config
            );
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("DeleteScope")
        .Produces<MessageResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithTags("Scopes")
        .WithOpenApi();

        // create client endpoint*******************************************************************
        group.MapPost("/clients", (
            CreateClientRequest req,
            AppConfig config
        ) =>
        {
            var result = ClientService.CreateClient(
                req,
                config
            );
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("CreateClient")
        .Produces<ClientObject>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithTags("Clients")
        .WithOpenApi();

        // update client endpoint*******************************************************************
        group.MapPut("/clients/{id}", (
            string id,
            ClientObject updated,
            AppConfig config
        ) =>
        {
            var result = ClientService.UpdateClient(id, updated, config);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("UpdateClient")
        .Produces<ClientObject>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithTags("Clients")
        .WithOpenApi();

        // set client feature flag endpoint*********************************************************
        group.MapPost("/client/options/{flag}", (HttpRequest req, string flag) =>
        {
            var form = req.ReadFormAsync().Result;
            var clientId = form["client_id"];
            var enabled = form["enabled"];

            if (ClientFeatures.Parse(flag) is not { } parsed)
                return ApiResult<MessageResponse>.Fail("Unknown feature flag", 400).ToHttpResult();

            if (string.IsNullOrWhiteSpace(clientId))
                return ApiResult<MessageResponse>.Fail("Missing client_id", 400).ToHttpResult();

            var isEnabled = bool.TryParse(enabled, out var result) && result;
            ClientFeaturesService.SetClientFeatureFlag(clientId, parsed, isEnabled);

            return ApiResult<MessageResponse>.Ok(new(true, $"Feature '{flag}' set to {isEnabled}")).ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("SetClientFeatureFlag")
        .WithTags("ClientFeatures")
        .WithOpenApi();

        // set client feature flag extended options endpoint****************************************
        group.MapPost("/client/options/{flag}/ext", (HttpRequest req, string flag) =>
        {
            var form = req.ReadFormAsync().Result;
            var clientId = form["client_id"];
            var options = form["options"];

            if (ClientFeatures.Parse(flag) is not { } parsed)
                return ApiResult<MessageResponse>.Fail("Unknown feature flag", 400).ToHttpResult();

            if (!ClientFeatures.GetHasExtendedOptions(parsed))
                return ApiResult<MessageResponse>.Fail("This feature has no extended options", 400).ToHttpResult();

            if (string.IsNullOrWhiteSpace(clientId))
                return ApiResult<MessageResponse>.Fail("Missing client_id", 400).ToHttpResult();

            ClientFeaturesService.SetFeatureOption(clientId, parsed, options);
            return ApiResult<MessageResponse>.Ok(new(true, $"Option for '{flag}' updated.")).ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("SetClientFeatureFlagExtended")
        .WithTags("ClientFeatures")
        .WithOpenApi();

        // get client feature flag enabled endpoint*************************************************
        group.MapGet("/client/options/{flag}", (HttpRequest req, string flag) =>
        {
            var clientId = req.Query["client_id"];

            if (ClientFeatures.Parse(flag) is not { } parsed)
                return ApiResult<MessageResponse>.Fail("Unknown feature flag", 400).ToHttpResult();

            if (string.IsNullOrWhiteSpace(clientId))
                return ApiResult<MessageResponse>.Fail("Missing client_id", 400).ToHttpResult();

            var enabled = ClientFeaturesService.IsFeatureEnabled(clientId, parsed);
            return ApiResult<MessageResponse>.Ok(new(true, enabled.ToString())).ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("GetClientFeatureFlagEnabled")
        .WithTags("ClientFeatures")
        .WithOpenApi();

        // get client feature flag extended options endpoint****************************************
        group.MapGet("/client/options/{flag}/ext", (HttpRequest req, string flag) =>
        {
            var clientId = req.Query["client_id"];

            if (ClientFeatures.Parse(flag) is not { } parsed)
                return ApiResult<MessageResponse>.Fail("Unknown feature flag", 400).ToHttpResult();

            if (!ClientFeatures.GetHasExtendedOptions(parsed))
                return ApiResult<MessageResponse>.Fail("This feature has no extended options", 400).ToHttpResult();

            if (string.IsNullOrWhiteSpace(clientId))
                return ApiResult<MessageResponse>.Fail("Missing client_id", 400).ToHttpResult();

            var options = ClientFeaturesService.GetFeatureOption(clientId, parsed);
            return ApiResult<MessageResponse>.Ok(new(true, options ?? "")).ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("GetClientFeatureFlagExtendedOptions")
        .WithTags("ClientFeatures")
        .WithOpenApi();

        // list clients endpoint********************************************************************
        group.MapGet("/clients", () =>
        {
            var result = ClientService.GetAllClients();
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("ListClients")
        .Produces<List<ClientObject>>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithTags("Clients")
        .WithOpenApi();

        // get client endpoint**********************************************************************
        group.MapGet("/clients/{id}", (string id) =>
        {
            var result = ClientService.GetClientById(id);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("GetClientById")
        .Produces<ClientObject>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status404NotFound)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithTags("Clients")
        .WithOpenApi();

        // get client id by name endpoint***********************************************************
        group.MapGet("/clients/id-by-name/{clientId}", (string clientId) =>
        {
            return ClientService.GetClientIdByIdentifier(clientId).ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("GetClientIdByClientIdentifier")
        .Produces<ApiResult<string>>(StatusCodes.Status200OK)
        .Produces<ApiResult<ErrorResponse>>(StatusCodes.Status404NotFound)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithTags("Clients")
        .WithOpenApi();

        // update client secret endpoint************************************************************
        group.MapPost("/clients/secret", async (
            ChangeClientSecretRequest req,
            AppConfig config
        ) =>
        {
            var result = ClientService.ChangeClientSecret(req, config);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("UpdateClientSecret")
        .Produces<MessageResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .Produces<ErrorResponse>(StatusCodes.Status404NotFound)
        .WithTags("Clients")
        .WithOpenApi();

        // delete client endpoint*******************************************************************
        group.MapDelete("/clients/{id}", (
            string id,
            AppConfig config
        ) =>
        {
            var result = ClientService.DeleteClient(
                id,
                config    
            );
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("DeleteClient")
        .Produces<MessageResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithTags("Clients")
        .WithOpenApi();

        // add a redirect URI to a client endpoint**************************************************
        group.MapPost("/clients/{clientId}/redirect-uris", (string clientId, [FromBody] string uri) =>
        {
            return ClientService.AddRedirectUri(clientId, uri).ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("AddRedirectUri")
        .Produces<ClientRedirectUriObject>(StatusCodes.Status201Created)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithTags("clients");

        // list all redirect URIs for a client endpoint*********************************************
        group.MapGet("/clients/{clientId}/redirect-uris", (string clientId) =>
        {
            return ClientService.GetRedirectUrisForClient(clientId).ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("GetRedirectUris")
        .Produces<List<string>>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .Produces<ErrorResponse>(StatusCodes.Status404NotFound)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithTags("clients");

        // delete a redirect URI from a client endpoint*********************************************
        group.MapDelete("/clients/redirect-uris", ([FromBody] string uri) =>
        {
            return ClientService.DeleteRedirectUri(uri).ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("DeleteRedirectUri")
        .Produces<MessageResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .Produces<ErrorResponse>(StatusCodes.Status404NotFound)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithTags("clients");

        // add scopes to client endpoint************************************************************
        group.MapPost("/clients/{clientId}/scopes", (
            string clientId,
            AssignScopesRequest req,
            AppConfig config
        ) =>
        {
            var result = ScopeService.AddScopesToClient(
                clientId,
                req,
                config
            );
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("AssignScopesToClient")
        .Produces<MessageResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithTags("Clients")
        .WithOpenApi();

        // get scopes for client endpoint**********************************************************
        group.MapGet("/clients/{id}/scopes", (string id) =>
        {
            var result = ScopeService.GetScopesForClient(id);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("ListClientScopes")
        .Produces<List<ScopeObject>>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithTags("Clients")
        .WithTags("Scopes")
        .WithOpenApi();

        // remove scope from client endpoint********************************************************
        group.MapDelete("/clients/{id}/scopes/{scopeId}", (
            string id,
            string scopeId,
            AppConfig config
        ) =>
        {
            var result = ScopeService.RemoveScopeFromClient(
                id,
                scopeId,
                config
            );

            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("RemoveScopeFromClient")
        .Produces<MessageResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithTags("Clients")
        .WithTags("Scopes")
        .WithOpenApi();

        // List scopes for a user endpoint**********************************************************
        group.MapGet("/users/{userId}/scopes", (string userId) =>
        {
            var result = ScopeService.ListScopesForUser(userId);
            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("ListUserScopes")
        .Produces<List<ScopeObject>>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithTags("Scopes")
        .WithTags("Users")
        .WithOpenApi();

        // assign scopes to a user endpoint*********************************************************
        group.MapPost("/users/{userId}/scopes", (
            string userId,
            AssignScopesRequest req,
            AppConfig config
        ) =>
        {
            var result = ScopeService.AddScopesToUser(
                userId,
                req,
                config
            );

            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("AssignScopesToUser")
        .Produces<MessageResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithOpenApi();

        // remove scope from user endpoint**********************************************************
        group.MapDelete("/users/{userId}/scopes/{scopeId}", (
            string userId,
            string scopeId
        ) =>
        {
            var result = ScopeService.RemoveScopeFromUser(
                userId,
                scopeId,
                config
            );

            return result.ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("RemoveUserScope")
        .Produces<MessageResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithOpenApi();

        // get audit logs endpoint******************************************************************
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
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
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
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
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
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithTags("Audit")
        .WithOpenApi();

        // token introspection endpoint*************************************************************
        group.MapPost("/introspect", (TokenIntrospectionRequest req, AppConfig config, HttpContext ctx) =>
        {
            var token = req.Token;

            if (string.IsNullOrWhiteSpace(token))
                return ApiResult<Dictionary<string, object>>
                    .Fail("Token is required", 400)
                    .ToHttpResult();

            var adminUserId = ctx.User.Claims.FirstOrDefault(c => c.Type == "sub")?.Value;
            var ip = ctx.Connection.RemoteIpAddress?.ToString();
            var ua = ctx.Request.Headers["User-Agent"].FirstOrDefault();

            return AuthService.IntrospectTokenAsAdmin(token, adminUserId, ip, ua, config).ToHttpResult();
        })
        .RequireAuthorization()
        .WithName("AdminIntrospectToken")
        .Produces<Dictionary<string, object>>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .Produces<ErrorResponse>(StatusCodes.Status403Forbidden)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithTags("Admin")
        .WithOpenApi();

        // generate TOTP QR code endpoint***********************************************************
        group.MapPost("/users/{id}/totp/generate", (
            string id,
            [FromBody] TotpQrRequest req,
            AppConfig config) =>
        {
            return UserService.GenerateTotpForUser(id, req.QrOutputPath, req.ClientId, config).ToHttpResult();
        })
        .RequireAuthorization()
        .WithTags("Users")
        .Produces<TotpQrResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithName("GenerateTotpQr");

        // verify TOTP code endpoint****************************************************************
        group.MapPost("/users/totp/verify", (
            [FromBody] VerifyTotpRequest req,
            AppConfig config) =>
        {
            return UserService.VerifyTotpCode(req.UserId, req.ClientId, req.Code, config).ToHttpResult();
        })
        .RequireAuthorization()
        .WithTags("Users")
        .Produces<MessageResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status403Forbidden)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithName("VerifyTotpCode");

        // disable TOTP for user endpoint***********************************************************
        group.MapPost("/users/{userId}/{clientId}/disable-totp",
            (string userId, string clientId, AppConfig config) =>
                UserService.DisableTotpForUser(userId, clientId, config).ToHttpResult())

        .RequireAuthorization()
        .WithName("DisableTotpForUser")
        .WithTags("TOTP")
        .Produces<MessageResponse>(StatusCodes.Status200OK)
        .Produces<ErrorResponse>(StatusCodes.Status400BadRequest)
        .Produces<ErrorResponse>(StatusCodes.Status404NotFound)
        .Produces<ErrorResponse>(StatusCodes.Status500InternalServerError)
        .WithOpenApi();

        return group;
    }
}