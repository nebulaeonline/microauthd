namespace microauthd.Common;

public enum PkceSessionAuthorizationResult
{
    MissingRequiredParameters,
    InvalidRedirectUri,
    MissingNonce,
    InvalidClientId,
    RedirectToSessionLogin,
    RedirectToFinalizeLogin,
    InternalServerError,
    ContinueWithHeadlessAuthorization,
}
