using madClient.Common;
using madTypes.Api.Requests;
using madTypes.Api.Responses;
using System.Text.Json.Serialization.Metadata;

namespace madClient.Serialization
{
    public static class ClientJsonResolver
    {
        public static JsonTypeInfo<T> GetJsonTypeInfo<T>()
        {
            object? resolved = typeof(T) switch
            {
                var t when t == typeof(TokenResponse) =>
                    MadClientJsonContext.Default.TokenResponse,

                var t when t == typeof(TokenRequest) =>
                    MadClientJsonContext.Default.TokenRequest,

                var t when t == typeof(MeResponse) =>
                    MadClientJsonContext.Default.MeResponse,

                var t when t == typeof(MessageResponse) =>
                    MadClientJsonContext.Default.MessageResponse,

                var t when t == typeof(RefreshTokenResponse) =>
                    MadClientJsonContext.Default.RefreshTokenResponse,

                var t when t == typeof(List<RefreshTokenResponse>) =>
                    MadClientJsonContext.Default.ListRefreshTokenResponse,

                var t when t == typeof(Dictionary<string, object>) =>
                    MadClientJsonContext.Default.DictionaryStringObject,

                _ => throw new InvalidOperationException(
                    $"JsonTypeInfo for {typeof(T).Name} not registered in MadClientJsonContext.")
            };

            return (JsonTypeInfo<T>)resolved!;
        }
    }
}
