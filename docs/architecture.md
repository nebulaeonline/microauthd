# microauthd
---
## Architecture
---

#### Introduction

microauthd doesn't aim to reinvent auth- it just strives to be leaner and more approachable than others in the space. The features are quite spartan for the time being, but that is by design. Most people don't need a full-fledged IdP, and the overhead associated with setting one up, maintaining it, and having the horsepower to run them right is quite a chore. So while microauthd isn't the easiest to setup yet (especially since it's young and we're not sure where the pain points will be), it should be far easier to understand the entire system and to configure it in the way you want.

#### High-Level Architecture: Separation of ADMIN & AUTH

The overall system layout is straightforward: microauthd runs two parallel kestrel instances, one for the ADMIN side and one for the AUTH side. Tokens issued by one side do not work on the other- for example an ADMIN token grants *zero* privileges on the AUTH side. Furthermore, routes and hosted files are not shared either- and this is not a trick of different prefixes or separate subfolders- they are two separate server instances running in one app that have different routes, different rules, different web hosting roots and different token signing keys. This was done intentionally to limit the fallout should anything go wrong. There are a few routes that allow administration from the AUTH side which can be used by assigning the correct scopes to an AUTH user account (or client account), but they are actually different routes with different functions backing them up (i.e. internally, CreateUser() and CreateUserScoped() are different functions). This was done to allow easier integration into people's applications; the endpoints handle basic user tasks like user creation, user listing, and password reset. The idea is to have a scoped account perform these privileged operations without giving those accounts full administrative privileges.

#### Architectural Philosophy

microauthd is written in a memory-safe language (C#), and has been engineered with two things in mind: (1) security: any place in the code or in the configuration where there was a question about security, the most secure option won out, bar none; and (2) performance: kestrel is known to be a nimble webserver, capable of handling extreme loads, and for the limited database schema used for microauthd, SQLite provided an excellent backend- up to a point. We may support other backends in the futre, but nothing is concrete at this point. Essentially it will boil down to user demand. A lot of fuss has been made about our lack of async code in the core product, and I will just say that a deliberate decision was made (not lightly) to avoid async in core paths, given SQLite's single-threaded nature and lack of async I/O support. We feel we made the right tradeoff *for now*. That being said, if at some point we choose to support different RDBMSs, that decision will be revisited.

#### Current Status

Currently, microauthd is a full featured OpenID Connect (OIDC) provider, exposing the standard endpoints (/token, /introspect, /.well-known/openid-configuration, /jwks.json) and if you enable PKCE support, /authorize and /login. Informal testing shows microauthd comfortably handling hundreds of requests per second for typical auth workloads, with well over 1,000 RPS possible in read-heavy or stateless configurations. SQLite’s simplicity and performance make it ideal for embedded and container-based deployments, though write-heavy workloads may benefit from eventual support for alternate database backends. Needless to say, it is not a pushover. 

Right now microauthd sits at a version of 0.8.x.y and there is no intent to bump it up to a 0.9.x.y series until features have stabilized. The time frame for a 1.0 release is sometime this summer and certainly by the end of the summer (August/September 2025 timeframe).

#### Community and Contributions

Contributors are welcome. This is a small project with big aspirations, but we understand that with auth, it takes time to build trust. That's why we made a couple of "micro" announcements early enough in the cycle to end up on people's radar. Ideally we will share our alpha and beta releases, and any and all constructive feedback is welcome.

Thanks for giving microauthd a try,

N