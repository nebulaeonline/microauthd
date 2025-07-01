**2025-06-25**

PKCE (Proof Key for Code Exchange) is now implemented. The example is served up from the public folder. ~~Empty this folder out if you don't want files served from it; I will likely add an option to enable/disable the static file hosting, but it is not implemented yet.~~ Fixed. Now, setting --serve-public-auth-files (or config file or env vars) enables the local webserver to serve static files from the /public subfolder of the microauthd working directory (defaults to false). Files will be served up as the root of the webserver (there will be no /public in the url). This is useful for serving up a simple login page or other static files that you want to be accessible from the auth server. The example login page can be removed to store your own files & assets.

PKCE is a security measure that mitigates the risk of authorization code interception attacks. It is primarily used in OAuth 2.0 and OpenID Connect flows to enhance security, especially for public clients (like mobile or single-page applications) that cannot securely store client secrets. It is similar to a challenge-response system. In the PKCE flow, the client generates a code verifier and a code challenge. The code verifier is a random string, while the code challenge is derived from the code verifier using a transformation method (usually SHA-256). When the client requests an authorization code, it includes the code challenge. Later, when exchanging the authorization code for an access token, the client must provide the original code verifier. The server then verifies that the code verifier matches the code challenge and issues the access token if they match.

**2025-06-24**

Some people are confused about what exactly microauthd is. You would use this instead of the built-in ASP.NET Core Identity system when you need real authentication across multiple platforms — not just a website. microauthd is built for shared login across web, SPA, mobile, and desktop apps, with proper token issuance, refresh, revocation, and machine-to-machine support. It separates identity from UI, so your backend services, CI jobs, and clients all speak the same auth language — without tying your auth logic to Razor Pages or EF Core.

It is important to note that although microauthd is written in C#, it is not tied to ASP.NET Core, or .NET Core at all except needing the .NET 8 runtime to run. It is designed to be used with any platform that can support Json Web Tokens (JWT) and can be used from any language that allows you to issue HTTP POST commands against a web endpoint (basically all of them). Don't be afriad of microauthd if you're not a .NET Core person or your platform is not running on .NET Core. This is quite common as systems like KeyCloak are written in Java and Authentik is written in Python.

~~I am going to begin working on the machinery needed to be reliably hosted behind a reverse proxy. This will include the forwarded headers along with support for trusted proxies. I hope to have this in an working by tomorrow.~~ (Done)

**2025-06-23**

I put together a client library (madAuthClient) to bridge the token-based authentication of microauthd with ASP.NET Core's cookie authentication. This allows you to use microauthd as a drop-in replacement for ASP.NET Core's built-in authentication system, while still using the same token-based authentication that microauthd provides. There is an example project in madRazorExample which uses this library to set up its auth provider.

~~Big changes coming to the audit logger. It was poorly thought out and implemented, so I'm going to be reworking it to use a more structured aproach. The current implementation is static and has no access to the HttpContext which results in many log entries having incorrect (or blank) values for the user id. Time to make it a bona-fide instance class and do it right. I should have the refactor done by tomorrow.~~ Done.

The web-based GUI threw the AOT compilation for a loop; this marks the end of the AOT compilation work for now. It is more important to have a robust web-based GUI than to shave 100ms off of startup time and 10-15MB of memory.

**2025-06-22**

Web-based GUI is available at `http://localhost:9041/Dashboard` (substitute your hostname / port as needed). 

Still working on the web-based management GUI. The Razor Pages implementation is progressing well and should be ready for initial testing soon. The project is a good demonstration of using microauthd's auth capabilities, as it generates all tokens and handles logins for the admin site.

**2025-06-21**

Working on a web-based management GUI. Currently implementing via Razor Pages, which will allow us to create a simple web interface for managing users, roles, permissions, scopes, and clients. About 10% of the way there, but it is a start.

Realized there wasn't an example login flow, so I added a simple example at public/login.html. The public/ folder in microauthd is used to serve static files, such as a login page or documentation. Any files placed in this folder will be available at the root of the AUTH server (e.g., /login.html). By default, login.html is included as a simple authentication interface.

You can customize the login experience by modifying this file or replacing it entirely. During build and publish, the contents of public/ are automatically copied to the output directory and served by the AUTH server.

The contract for the login page is that it should POST to `/token` with the following fields / parameters: grant_type=password, username, password, and client_id (should mirror the client you set up during OOBE). You can also refresh at `/token` with grant_type = refresh_token and token set to the refresh token value obtained with the original token grant.

**2025-06-20**

Started separating the data layer from the service layer internally. This will allow us to swap out the data layer in the future without affecting the service logic. There is currently no plan to abandon SQLite, so this will be an ongoing background process.

We haven't had a lot of time to test the bindings, so please stay tuned for updates on that front. The idea was to get *something* out there for people to use, but we will be actively auditing for full coverage and putting together testsuites for each of the sets of bindings.

**2025-06-19**

Bindings are up for Python, Go, and JS/TS. Please consider all of them a work in progress, but the should be usable for most operations (both AUTH & ADMIN).

So the cli tool `mad` is now in a pretty good state, but it is **slow**. And not just a little slow, but *really* slow. That is fine for the time being, because it is a cli bootstrapping tool mostly, it is not expected that heavy scripting will be done using it. I figure most people will code against the JSON HTTP APIs directly, and those are plenty fast. I just wanted to give people a heads up that the CLI is not fast. Know that it is not microauthd itself.

**2025-06-18**

~~Things are a bit in flux at the moment. Some things are broken.~~ Token introspection and token revocation should be solid again.

~~We are going to be implementing TOTP-based login in the next day or so, so the repo might be in flux for a bit. 0.7.1.4 is a stable release for testing purposes.~~

TOTP-based login is now implemented and will be undergoing testing. Stick at 7.1.4 for now if you want something stable to play with. The way TOTP works is that a request is made to generate a QR code, and then the user has to verify before it is set to active. We also added an endpoint to validate username/password without issuing a token, so expected login flows of validating user/pass and then MFA via TOTP works as generally implemented elsewhere. TOTP can also be disabled via JSON/HTTP API.

Remember please that the database schema is still in flux, and we do not provide migrations yet, so you will need to drop the database and re-run the OOBE wizard. When we go stable, we will begin providing db migrations.

**2025-06-17**

CRUD operations are now implemented for our 5 main data types: users, roles, permissions, clients, and scopes. The API is now consistent across all endpoints, with uniform response structures and error handling. The `mad` CLI tool has also been significantly improved to support these operations.

The python test harness is now complete and has been used to validate the API surface, the back-end functions and the `mad` CLI tool. `mad` can now be used to create, update, delete, and assign users, roles, permissions, clients, and scopes. Additional tests will be added for token grant, revocation and refresh token redemption (all 3 have been tested manually and via script and the system does work as intended).

**2025-06-16**

microauthd is currently not yet ready for production use. It has a LOT of rough edges right now. The code is functional and has been tested in a few scenarios, but it is most definitely not ready for production use. There is no documentation yet, either.

Please read on to understand its current capabilities, design philosophy, real-world security posture, known limitations, and how it will evolve toward a production-ready release.

Understand that this is **NOT A PRODUCTION READY SYSTEM**. It is not even suitable for testing in production-like environments yet. It is a work in progress.