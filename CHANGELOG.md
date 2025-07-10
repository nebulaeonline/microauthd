**2025-07-02**

TOTP is working again, and we added an --otp-issuer option so that you can control how your entry will appear in authentication apps like Google Authenticator; it was previously hardcoded to microauthd, but we didn't like that look.

Added a new token inspector for both `mad` cli and for the ADMIN web gui. Now you can paste raw tokens in and have them decoded locally. I've wanted this functionality since the outset, so I'm glad it's finally done.

The march continues for bringing our tokens and our token issuance into compliance with OAuth2 and OIDC. Fixed a bug where Id Tokens were not being issued in the case of refresh, even if the original token had an openid scope. Also updated /userinfo to bring it into compliance with OAuth2 specifications.

**2025-07-01**

Big changes in bringing several of the API responses into RFC compliance with OAuth2 & OIDC. This included a new error object and the expansion of our ApiResponse to include the new object. Testing has gone well, but things may be screwy here or there until the dust settles.

The next big project in preparation for an alpha release is to solidify API responses and make them uniform. What I am specifically going to focus on is returning 404 errors where appropriate rather than blanket 400 errors. It'll be a big project, but it will bring clarity to consumers of the JSON/HTTP APIs.

Made a lot of progress today with implementing standard login flows expected by OAuth2 and OIDC clients. This lays the groundwork for acting as a client rather than a server for 3rd party logins and federated IAM/IdP systems. Demos for both flows are in the /public directory.

**2025-06-30**

The testsuite is rounding into shape. Normally I would have been writing tests as I went, but this one is a bit trickier than most. We have the end-to-end testing via the Python suite, which hits the CRUD on every endpoint including token issuance, renewal and invalidation testing. But there's a lot of standalone and database functions that don't get e2e testing via Python, and so I'm filling in the blanks. It's about 90% of the way done. I hope to have close to 100% coverage within the next week or so, so you can rest assured that microauthd is being worked out from a testing perspective.

**2025-06-29**

The OOBE tool has been separated into a standalone project called `madOobe`. It will still run as part of microauthd, but is accessible as a standalone tool for those who need it (Docker users primarily). You can start microauthd with --docker to prevent the OOBE tool from running as part of the first run.

I am working on packaging this up for Windows, Linux, and MacOS. The Linux build will also include a Docker image that can optionally be used to run microauthd in a container.

**2025-06-28**

On the usability front, I just wanted to say I'm happy about finally versioning our database schema for migrations, and now no longer requiring `mad` users to enter --admin-url on the CLI. We are slowly getting to a usability point that I think can drive adoption of microauthd. Additionally, if you are experimenting with the package, we would like to hear from you. Pain points, missing features, whatever. As we seek to move to a true v1.0 release, it will be important to get feedback so we can get things in order. Don't be shy. Thanks!

If you don't feel comfortable reaching out via GitHub issues, you can always email me at nebulae at nebulae dot online.

**2025-06-27**

Today we introduced Id Token issuance in compliance with OpenID Connect. This allows microauthd to issue ID tokens alongside access tokens, providing a standardized way to convey user identity and authentication information. The ID token is a JWT that contains claims about the authenticated user, such as their unique identifier, email, and other profile information.

On performance, changing the hashing strategy for refresh tokens to use SHA-256 only instead of Argon2id and SHA-256 brought another 50% speedup, bringing us to around 60rps with bursts to 1500 rps.

We now cache password hashes (if enabled); the feature and duration are configurable via --enable-pass-cache and --pass-cache-duration (default is 5 minutes). We are now seeing throughput of over 600 rps, with burst at 3,000 rps. This means microauthd is now performing on par or better than its peers.

We have implemented db schema versioning, which will allow us to upgrade painlessly in the future. If you have started with a version prior to the last few days, you should be fine. Users on much older versions may have to do some surgery. Let us know if you need assistance.

Big change with `mad` CLI tool: it now uses a persistent admin url that is set the first time you run `mad session login`. For commands issued after that, you can omit the --admin-url cli option and it will just work. Thank goodness- that was my least favorite part of mad.

**2025-06-26**

So why is microauthd slow? Well, it is secure. The truth is that microauthd is cpu limited- it does a lot of argon2id hashing (and verifying) in the name of security; so depending upon your settings, you *will* notice it. Token issuance profiling shows 30%+ of microauthd's time is spent verifying the username & password, 30%+ of time is spent verifying the client id & client secret, and 30%+ of the time is spent generating the refresh token. What does this mean? Argon2id is deliberately expensive, and it means we're cpu bound, something async'ing all the things will not fix. It means that in the name of security, we are always going to be cpu bound. There's a few tracks we can take- we can verify the client secret by a different hash, we can cache the client secrets, and we can tone down the argon2id parameters (we run at 2 time cost / 2 parallelism / and 32MB memory). That would probably altogether result in a 40% speedup (not insignificant). But microauthd values security above all other things. So where is it falling now? ~20rps bursting to 1100rps. Not super fast. But is it suitable for 90% of the sites out there? Yes. So just keep that in mind when evaluating microauthd. I was getting < 1 rps on KeyCloak and Authentik, so we're at least in the ballpark. These benchmarks were run with 5,000 requests and 50 concurrent requests.

microauthd isn't built to be the fastest- it's built to be **secure**, **transparent**, and **manageable**. If you're running an API with tens of millions of users, you may outgrow it. But for 99% of modern apps, it's more than fast enough. So when you evaluate microauthd, keep this in mind: Security-first means CPU-first, and we wouldn't have it any other way.

Adding client secret caching brought about a 50% speedup in token issuance, and now microauthd is hovering around 30rps with bursts to 1200rps. This is a significant improvement.

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