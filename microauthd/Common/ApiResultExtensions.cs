using madTypes.Api.Common;
using madTypes.Api.Responses;
using madTypes.Common;
using System.Text.Json.Serialization.Metadata;
using Microsoft.AspNetCore.Http;
namespace microauthd.Common
{
    public static class ApiResultExtensions
    {
        /// <summary>
        /// Converts an <see cref="ApiResult{T}"/> to an HTTP response result.
        /// </summary>
        /// <remarks>This method handles both successful and error cases of the <see
        /// cref="ApiResult{T}"/>: <list type="bullet"> <item> <description>If <paramref name="result"/> is successful,
        /// the value is serialized as JSON and returned with the status code specified in <see
        /// cref="ApiResult{T}.StatusCode"/>.</description> </item> <item> <description>If <paramref name="result"/>
        /// contains an error and the value is an <see cref="OidcErrorResponse"/>, the error object is serialized as
        /// JSON using the appropriate type information.</description> </item> <item> <description>For all other error
        /// cases, a generic error response is returned as JSON with the error message and a success flag set to <see
        /// langword="false"/>.</description> </item> </list></remarks>
        /// <typeparam name="T">The type of the value contained in the <see cref="ApiResult{T}"/>.</typeparam>
        /// <param name="result">The <see cref="ApiResult{T}"/> to convert to an HTTP response.</param>
        /// <returns>An <see cref="IResult"/> representing the HTTP response. If the operation was successful, the response
        /// contains the value of the <see cref="ApiResult{T}"/> serialized as JSON with the appropriate status code. If
        /// the operation failed, the response contains an error object serialized as JSON with the appropriate status
        /// code.</returns>
        public static IResult ToHttpResult<T>(this ApiResult<T> result)
        {
            if (result.Success)
            {
                return Results.Json(
                    result.Value!,
                    ApiResultExtensions.GetJsonTypeInfo<T>(),
                    statusCode: result.StatusCode
                );
            }

            // If error is an OIDC error object
            if (result.Value is OidcErrorResponse oidcError)
            {
                return Results.Json(
                    oidcError,
                    MicroauthdJsonContext.Default.OidcErrorResponse,
                    statusCode: result.StatusCode
                );
            }

            // Default fallback: return error message as flat object
            var error = new ErrorResponse(false, result.Error ?? "An error occurred");

            return Results.Json(
                error,
                MicroauthdJsonContext.Default.ErrorResponse,
                statusCode: result.StatusCode
            );
        }

        /// <summary>
        /// Retrieves the <see cref="JsonTypeInfo{T}"/> for the specified type <typeparamref name="T"/>.
        /// </summary>
        /// <remarks>This method uses a predefined mapping of types to their corresponding <see
        /// cref="JsonTypeInfo{T}"/> instances within the <c>MicroauthdJsonContext</c>. If the type <typeparamref
        /// name="T"/> is not registered, an <see cref="InvalidOperationException"/> is thrown.</remarks>
        /// <typeparam name="T">The type for which to retrieve the JSON type information.</typeparam>
        /// <returns>The <see cref="JsonTypeInfo{T}"/> instance associated with the specified type <typeparamref name="T"/>.</returns>
        /// <exception cref="InvalidOperationException">Thrown if the JSON type information for the specified type <typeparamref name="T"/> is not registered in
        /// <c>MicroauthdJsonContext</c>.</exception>
        public static JsonTypeInfo<T> GetJsonTypeInfo<T>()
        {
            object? resolved = typeof(T) switch
            {
                var t when t == typeof(List<string>) =>
                    MicroauthdJsonContext.Default.ListString,

                var t when t == typeof(AccessCheckResponse) =>
                    MicroauthdJsonContext.Default.AccessCheckResponse,

                var t when t == typeof(AuditLogResponse) =>
                    MicroauthdJsonContext.Default.AuditLogResponse,

                var t when t == typeof(List<AuditLogResponse>) =>
                    MicroauthdJsonContext.Default.ListAuditLogResponse,

                var t when t == typeof(ClientObject) =>
                    MicroauthdJsonContext.Default.ClientObject,

                var t when t == typeof(List<ClientObject>) =>
                    MicroauthdJsonContext.Default.ListClientObject,

                var t when t == typeof(ClientRedirectUriObject) =>
                    MicroauthdJsonContext.Default.ClientRedirectUriObject,

                var t when t == typeof(List<ClientRedirectUriObject>) =>
                    MicroauthdJsonContext.Default.ListClientRedirectUriObject,

                var t when t == typeof(Dictionary<string, object>) =>
                    MicroauthdJsonContext.Default.DictionaryStringObject,

                var t when t == typeof(ErrorResponse) =>
                    MicroauthdJsonContext.Default.ErrorResponse,

                var t when t == typeof(JwksResponse) =>
                    MicroauthdJsonContext.Default.JwksResponse,

                var t when t == typeof(MeResponse) =>
                    MicroauthdJsonContext.Default.MeResponse,

                var t when t == typeof(MessageResponse) =>
                    MicroauthdJsonContext.Default.MessageResponse,

                var t when t == typeof(OidcErrorResponse) =>
                    MicroauthdJsonContext.Default.OidcErrorResponse,

                var t when t == typeof(OidcDiscoveryResponse) =>
                    MicroauthdJsonContext.Default.OidcDiscoveryResponse,

                var t when t == typeof(PermissionAssignmentDto) =>
                    MicroauthdJsonContext.Default.PermissionAssignmentDto,

                var t when t == typeof(PermissionDto) =>
                    MicroauthdJsonContext.Default.PermissionDto,

                var t when t == typeof(List<PermissionDto>) =>
                    MicroauthdJsonContext.Default.ListPermissionDto,

                var t when t == typeof(PermissionObject) =>
                    MicroauthdJsonContext.Default.PermissionObject,

                var t when t == typeof(List<PermissionObject>) =>
                    MicroauthdJsonContext.Default.ListPermissionObject,

                var t when t == typeof(PingResponse) =>
                    MicroauthdJsonContext.Default.PingResponse,

                var t when t == typeof(RefreshTokenResponse) =>
                    MicroauthdJsonContext.Default.RefreshTokenResponse,

                var t when t == typeof(List<RefreshTokenResponse>) =>
                    MicroauthdJsonContext.Default.ListRefreshTokenResponse,

                var t when t == typeof(RevokeResponse) =>
                    MicroauthdJsonContext.Default.RevokeResponse,

                var t when t == typeof(RoleAssignmentDto) =>
                    MicroauthdJsonContext.Default.RoleAssignmentDto,

                var t when t == typeof(RoleDto) =>
                    MicroauthdJsonContext.Default.RoleDto,

                var t when t == typeof(List<RoleDto>) =>
                    MicroauthdJsonContext.Default.ListRoleDto,

                var t when t == typeof(RoleObject) =>
                    MicroauthdJsonContext.Default.RoleObject,

                var t when t == typeof(List<RoleObject>) =>
                    MicroauthdJsonContext.Default.ListRoleObject,

                var t when t == typeof(ScopeAssignmentDto) =>
                    MicroauthdJsonContext.Default.ScopeAssignmentDto,

                var t when t == typeof(ScopeDto) =>
                    MicroauthdJsonContext.Default.ScopeDto,

                var t when t == typeof(List<ScopeDto>) =>
                    MicroauthdJsonContext.Default.ListScopeDto,

                var t when t == typeof(ScopeObject) =>
                    MicroauthdJsonContext.Default.ScopeObject,

                var t when t == typeof(List<ScopeObject>) =>
                    MicroauthdJsonContext.Default.ListScopeObject,

                var t when t == typeof(SessionResponse) =>
                    MicroauthdJsonContext.Default.SessionResponse,

                var t when t == typeof(string) =>
                    MicroauthdJsonContext.Default.String,

                var t when t == typeof(List<SessionResponse>) =>
                    MicroauthdJsonContext.Default.ListSessionResponse,

                var t when t == typeof(TokenResponse) =>
                    MicroauthdJsonContext.Default.TokenResponse,

                var t when t == typeof(TotpQrResponse) =>
                    MicroauthdJsonContext.Default.TotpQrResponse,

                var t when t == typeof(UserObject) =>
                    MicroauthdJsonContext.Default.UserObject,

                var t when t == typeof(List<UserObject>) =>
                    MicroauthdJsonContext.Default.ListUserObject,

                var t when t == typeof(VerifyPasswordResponse) =>
                    MicroauthdJsonContext.Default.VerifyPasswordResponse,

                var t when t == typeof(VersionResponse) =>
                    MicroauthdJsonContext.Default.VersionResponse,

                var t when t == typeof(WhoamiResponse) =>
                    MicroauthdJsonContext.Default.WhoamiResponse,

                _ => throw new InvalidOperationException(
                    $"JsonTypeInfo for {typeof(T).Name} not registered in MicroauthJsonContext.")
            };

            return (JsonTypeInfo<T>)resolved!;
        }
    }
}
