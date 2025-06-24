# madAuthClient

**madAuthClient** is a lightweight client library for bridging [microauthd](https://github.com/your-org/microauthd)'s token-based authentication with ASP.NET Core's cookie-based login system.

It is designed to support secure, drop-in login flows for Razor Pages or MVC apps that interact with a `microauthd` AUTH server.

### Features

- Login via username/password using `client_id` + `client_secret`
- Automatic cookie sign-in and sign-out support
- JWT claim extraction to enrich user sessions
- Transparent token refresh middleware
- Works cleanly with DI (`AddMadAuthClient`)
- No external dependencies beyond `Microsoft.Extensions.Http`

### Getting Started

This package is designed to be integrated into ASP.NET Core web apps.

For a full example and walkthrough, see the [madRazorExample](../madRazorExample/README.md) project.