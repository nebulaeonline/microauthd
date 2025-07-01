using madTypes.Api.Responses;
using madTypes.Common;
using System.Net;

namespace microauthd.Common;

public static class OidcErrors
{
    /// <summary>
    /// Creates an <see cref="ApiResult{T}"/> representing an "invalid_grant" error response.
    /// </summary>
    /// <typeparam name="T">The type of the result object associated with the API response.</typeparam>
    /// <param name="description">A description of the error, providing additional context for the "invalid_grant" error.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing an <see cref="OidcErrorResponse"/> with the error set to
    /// "invalid_grant"  and the specified error description, along with an HTTP status code of 400.</returns>
    public static ApiResult<T> InvalidGrant<T>(string? description = null)
    {
        return ApiResult<T>.FailObj(new OidcErrorResponse
        {
            Error = "invalid_grant",
            ErrorDescription = description ?? "Invalid credentials"
        }, 400);
    }

    /// <summary>
    /// Creates an API result indicating that the client authentication failed.
    /// </summary>
    /// <typeparam name="T">The type of the data payload in the API result.</typeparam>
    /// <param name="description">A description of the error, providing additional context for the failure.</param>
    /// <returns>An <see cref="ApiResult{T}"/> representing the failure, with an error code of <c>"invalid_client"</c> and an
    /// HTTP status code of 401.</returns>
    public static ApiResult<T> InvalidClient<T>(string? description = null)
    {
        return ApiResult<T>.FailObj(new OidcErrorResponse
        {
            Error = "invalid_client",
            ErrorDescription = description ?? "Invalid credentials"
        }, 401);
    }

    /// <summary>
    /// Creates an API result indicating that the request is invalid.
    /// </summary>
    /// <typeparam name="T">The type of the result's data payload.</typeparam>
    /// <param name="description">An optional description of the error. If not provided, a default message of "Invalid request" is used.</param>
    /// <returns>An <see cref="ApiResult{T}"/> representing a failed operation with an "invalid_request" error and an HTTP status
    /// code of 400.</returns>
    public static ApiResult<T> InvalidRequest<T>(string? description = null)
    {
        return ApiResult<T>.FailObj(new OidcErrorResponse
        {
            Error = "invalid_request",
            ErrorDescription = description ?? "Invalid request"
        }, 400);
    }

    /// <summary>
    /// Generates a redirect response to the specified URI with OpenID Connect (OIDC) error details appended as query
    /// parameters.
    /// </summary>
    /// <remarks>This method is typically used in OpenID Connect flows to handle error scenarios by
    /// redirecting the client to a specified URI with error information encoded in the query string. The resulting URI
    /// will include the following query parameters: <list type="bullet"> <item> <description><c>error</c>: The error
    /// code provided in the <paramref name="error"/> parameter.</description> </item> <item>
    /// <description><c>error_description</c>: The optional error description provided in the <paramref
    /// name="description"/> parameter, if specified.</description> </item> <item> <description><c>state</c>: The
    /// optional state value provided in the <paramref name="state"/> parameter, if specified.</description> </item>
    /// </list> If the <paramref name="redirectUri"/> already contains query parameters, the error details will be
    /// appended to the existing query string.</remarks>
    /// <param name="redirectUri">The base URI to which the client will be redirected. Must not be null or empty.</param>
    /// <param name="error">The error code indicating the type of OIDC error. Must not be null or empty.</param>
    /// <param name="description">An optional human-readable description of the error. If provided, it will be included as a query parameter.</param>
    /// <param name="state">An optional state value to maintain state between the request and the callback. If provided, it will be included
    /// as a query parameter.</param>
    /// <returns>An <see cref="IResult"/> that redirects the client to the specified URI with the error details included in the
    /// query string.</returns>
    public static IResult OidcRedirectError(string redirectUri, string error, string? description = null, string? state = null)
    {
        var query = new Dictionary<string, string>
        {
            ["error"] = error
        };

        if (!string.IsNullOrWhiteSpace(description))
            query["error_description"] = description;

        if (!string.IsNullOrWhiteSpace(state))
            query["state"] = state;

        var queryString = string.Join("&", query.Select(kvp =>
            $"{WebUtility.UrlEncode(kvp.Key)}={WebUtility.UrlEncode(kvp.Value)}"));

        var redirectUrl = redirectUri.Contains('?')
            ? $"{redirectUri}&{queryString}"
            : $"{redirectUri}?{queryString}";

        return Results.Redirect(redirectUrl);
    }
}
