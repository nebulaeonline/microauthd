# madRazorExample

This project demonstrates how to integrate a Razor Pages application with a `microauthd` AUTH server using the `madAuthClient` library. It shows you how to handle secure login, persistent session cookies, automatic token refresh, and logout — all using clean, idiomatic ASP.NET Core patterns.

At the heart of the flow is `madAuthClient`, which performs the token request (`grant_type=password`), extracts and builds claims from the resulting JWT, and signs in the user using a standard cookie-based identity. This enables your app to interact with the `microauthd` AUTH server like any other OAuth2-compliant backend, while still providing a familiar Razor Pages login experience for users.

The login flow begins with a simple `Login.cshtml.cs` model that uses a DI `MadAuthClient` to authenticate a user:

```csharp

var token = await _madAuthClient.LoginAsync(username, password);
var claims = ClaimsBuilder.FromToken(token);
await TokenToCookieBridge.SignInAsync(HttpContext, token, claims);

```

---

Once signed in, the user is authenticated via cookie, and their session is automatically refreshed behind the scenes using a middleware component that checks the token’s expiration (and reissues a fresh one if needed). This keeps sessions active and seamless, without requiring the user to log in again or handle tokens manually.

The app includes a secure page (/SecurePage) protected with [Authorize], which displays user claims and allows them to logout. The logout handler signs the user out and revokes the current access token via madAuthClient, ensuring the session is terminated on both client and server sides.

To see how this is wired together, or to start building your own app using madAuthClient, review Program.cs, Login.cshtml.cs, and SecurePage.cshtml. You’ll see how little code is required to achieve a robust and secure integration with microauthd.

It's important to note that you should store your client secret in a secure manner, unlike the example here which uses a hardcoded value. In production, consider using an envinronment variable or a secure file (or even a secure vault depending on platform). Something like this:

```csharp

ClientSecret = Environment.GetEnvironmentVariable("MAD_CLIENT_SECRET") ?? throw new InvalidOperationException("MAD_CLIENT_SECRET is not set")

```