using madTypes.Api.Common;
using madTypes.Api.Responses;
using madTypes.Common;
using System.Text.Json.Serialization.Metadata;

namespace microauthd.Common
{
    public static class ApiResultExtensions
    {
        public static IResult ToHttpResult<T>(this ApiResult<T> result)
        {
            return result.Success
                ? Results.Json(result.Value!, ApiResultExtensions.GetJsonTypeInfo<T>(), statusCode: result.StatusCode)
                : Results.Json(new ErrorResponse(false, result.Error ?? "An error occurred"), MicroauthJsonContext.Default.ErrorResponse, statusCode: result.StatusCode);
        }

        public static JsonTypeInfo<T> GetJsonTypeInfo<T>()
        {
            object? resolved = typeof(T) switch
            {
                var t when t == typeof(List<string>) =>
                    MicroauthJsonContext.Default.ListString,

                var t when t == typeof(AccessCheckResponse) =>
                    MicroauthJsonContext.Default.AccessCheckResponse,

                var t when t == typeof(AuditLogResponse) =>
                    MicroauthJsonContext.Default.AuditLogResponse,

                var t when t == typeof(List<AuditLogResponse>) =>
                    MicroauthJsonContext.Default.ListAuditLogResponse,

                var t when t == typeof(ClientObject) =>
                    MicroauthJsonContext.Default.ClientObject,

                var t when t == typeof(List<ClientObject>) =>
                    MicroauthJsonContext.Default.ListClientObject,

                var t when t == typeof(CreatedResponse) =>
                    MicroauthJsonContext.Default.CreatedResponse,

                var t when t == typeof(List<CreatedResponse>) =>
                    MicroauthJsonContext.Default.ListCreatedResponse,

                var t when t == typeof(Dictionary<string, object>) =>
                    MicroauthJsonContext.Default.DictionaryStringObject,

                var t when t == typeof(ErrorResponse) =>
                    MicroauthJsonContext.Default.ErrorResponse,

                var t when t == typeof(JwksResponse) =>
                    MicroauthJsonContext.Default.JwksResponse,

                var t when t == typeof(MeResponse) =>
                    MicroauthJsonContext.Default.MeResponse,

                var t when t == typeof(MessageResponse) =>
                    MicroauthJsonContext.Default.MessageResponse,

                var t when t == typeof(OidcDiscoveryResponse) =>
                    MicroauthJsonContext.Default.OidcDiscoveryResponse,

                var t when t == typeof(PermissionObject) =>
                    MicroauthJsonContext.Default.PermissionObject,

                var t when t == typeof(List<PermissionObject>) =>
                    MicroauthJsonContext.Default.ListPermissionObject,

                var t when t == typeof(PingResponse) =>
                    MicroauthJsonContext.Default.PingResponse,

                var t when t == typeof(RefreshTokenResponse) =>
                    MicroauthJsonContext.Default.RefreshTokenResponse,

                var t when t == typeof(List<RefreshTokenResponse>) =>
                    MicroauthJsonContext.Default.ListRefreshTokenResponse,

                var t when t == typeof(RevokeResponse) =>
                    MicroauthJsonContext.Default.RevokeResponse,

                var t when t == typeof(RoleObject) =>
                    MicroauthJsonContext.Default.RoleObject,

                var t when t == typeof(List<RoleObject>) =>
                    MicroauthJsonContext.Default.ListRoleObject,

                var t when t == typeof(ScopeObject) =>
                    MicroauthJsonContext.Default.ScopeObject,

                var t when t == typeof(List<ScopeObject>) =>
                    MicroauthJsonContext.Default.ListScopeObject,

                var t when t == typeof(SessionResponse) =>
                    MicroauthJsonContext.Default.SessionResponse,

                var t when t == typeof(string) =>
                    MicroauthJsonContext.Default.String,

                var t when t == typeof(List<SessionResponse>) =>
                    MicroauthJsonContext.Default.ListSessionResponse,

                var t when t == typeof(TokenResponse) =>
                    MicroauthJsonContext.Default.TokenResponse,

                var t when t == typeof(TotpQrResponse) =>
                    MicroauthJsonContext.Default.TotpQrResponse,

                var t when t == typeof(UserObject) =>
                    MicroauthJsonContext.Default.UserObject,

                var t when t == typeof(List<UserObject>) =>
                    MicroauthJsonContext.Default.ListUserObject,

                var t when t == typeof(VerifyPasswordResponse) =>
                    MicroauthJsonContext.Default.VerifyPasswordResponse,

                var t when t == typeof(VersionResponse) =>
                    MicroauthJsonContext.Default.VersionResponse,

                var t when t == typeof(WhoamiResponse) =>
                    MicroauthJsonContext.Default.WhoamiResponse,

                _ => throw new InvalidOperationException(
                    $"JsonTypeInfo for {typeof(T).Name} not registered in MicroauthJsonContext.")
            };

            return (JsonTypeInfo<T>)resolved!;
        }
    }
}
