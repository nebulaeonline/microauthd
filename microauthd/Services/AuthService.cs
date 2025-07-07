using madTypes.Api.Common;
using madTypes.Api.Requests;
using madTypes.Api.Responses;
using madTypes.Common;
using microauthd.Common;
using microauthd.Config;
using microauthd.Data;
using microauthd.Tokens;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.IdentityModel.Tokens;
using OtpNet;
using Serilog;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using static nebulae.dotArgon2.Argon2;

namespace microauthd.Services;

public static class AuthService
{
    /// <summary>
    /// A cryptographic random byte array used as a pepper for password caching operations.
    /// </summary>
    /// <remarks>This static field contains a 32-byte cryptographic random value generated using  <see
    /// cref="System.Security.Cryptography.RandomNumberGenerator"/>. It is intended to  add an additional layer of
    /// security to password caching mechanisms by introducing  unpredictability.</remarks>
    private static byte[] _passCachePepper = RandomNumberGenerator.GetBytes(32);

    /// <summary>
    /// Tracks the elapsed time since the last login operation.
    /// </summary>
    /// <remarks>This stopwatch is initialized and started immediately upon application startup. It can be
    /// used to measure the time elapsed since the last login-related activity.</remarks>
    private static readonly Stopwatch _lastLogin = Stopwatch.StartNew();

    /// <summary>
    /// Regenerates the cryptographic pepper used for password caching.
    /// </summary>
    /// <remarks>This method generates a new random 32-byte pepper and clears the password cache to ensure
    /// that previously cached passwords are invalidated. It is typically used to enhance security by periodically
    /// refreshing the pepper.</remarks>
    public static void RegeneratePepperAndClearCache()
    {
        _passCachePepper = RandomNumberGenerator.GetBytes(32);
        _passwordCache.Clear();
        Log.Information("Password cache pepper regenerated.");
    }

    /// <summary>
    /// A static memory cache used to store password-related data with a size limit of 500 entries.
    /// </summary>
    /// <remarks>This cache is configured with a size limit of 500 entries to manage memory usage effectively.
    /// It is intended for internal use and should not be accessed directly outside of the class.</remarks>
    private static readonly MemoryCache _passwordCache = new (new MemoryCacheOptions
    {
        SizeLimit = 500
    });

    /// <summary>
    /// Generates a cache key based on the provided user ID and password.
    /// </summary>
    /// <remarks>The cache key is derived by hashing the combination of the user ID, password, and an internal
    /// pepper value. This ensures that the resulting key is unique and secure.</remarks>
    /// <param name="userId">The unique identifier of the user. Cannot be null or empty.</param>
    /// <param name="password">The user's password. Cannot be null or empty.</param>
    /// <returns>A base64-encoded string representing the computed cache key.</returns>
    private static string GetPassCacheKey(string userId, string password)
    {
        using var sha = SHA256.Create();
        var input = Encoding.UTF8.GetBytes($"{userId}:{password}");
        var combined = input.Concat(_passCachePepper).ToArray();
        var hash = sha.ComputeHash(combined);
        return Convert.ToBase64String(hash);
    }

    /// <summary>
    /// A static memory cache used to store client secrets with a size limit of 100 entries.
    /// </summary>
    /// <remarks>This cache is intended for temporary storage of client secrets to improve performance by
    /// reducing repeated retrievals. The size limit ensures that the cache does not grow indefinitely.</remarks>
    private static readonly MemoryCache _clientSecretCache = new(new MemoryCacheOptions
    {
        SizeLimit = 100
    });

    /// <summary>
    /// Removes the cached client secret associated with the specified client ID.
    /// </summary>
    /// <remarks>This method invalidates the cached client secret for the given client ID, ensuring that
    /// subsequent operations requiring the client secret will not use outdated or stale data.</remarks>
    /// <param name="clientId">The unique identifier of the client whose cached secret should be invalidated. Must not be <see
    /// langword="null"/> or empty.</param>
    public static void InvalidateClientCache(string clientId)
    {
        _clientSecretCache.Remove(clientId);
    }

    /// <summary>
    /// Generates a random password of the specified length using a mix of alphanumeric characters and symbols.
    /// </summary>
    /// <remarks>The generated password includes a combination of lowercase letters, uppercase letters,
    /// digits,  and special characters to ensure complexity. The method uses a cryptographically secure random  number
    /// generator to ensure randomness.</remarks>
    /// <param name="length">The desired length of the password. Must be at least 8 characters.</param>
    /// <returns>A randomly generated password string of the specified length.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="length"/> is less than 8.</exception>
    public static string GeneratePassword(int length)
    {
        if (length < 8)
            throw new ArgumentOutOfRangeException(nameof(length), "Minimum length is 8 characters.");

        const string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}";
        var password = new StringBuilder(length);
        var bytes = new byte[length];

        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(bytes);

        for (int i = 0; i < length; i++)
        {
            var idx = bytes[i] % charset.Length;
            password.Append(charset[idx]);
        }

        return password.ToString();
    }

    /// <summary>
    /// Generates a secure hash for the specified password using the Argon2id algorithm.
    /// </summary>
    /// <remarks>This method uses the Argon2id algorithm to securely hash the password. The hashing
    /// process includes generating a random salt of the specified length and applying the configured Argon2
    /// parameters for time, memory, and parallelism. The resulting hash is encoded as a string for storage or
    /// comparison.</remarks>
    /// <param name="password">The password to be hashed. Cannot be null or empty.</param>
    /// <param name="config">The application configuration containing Argon2 parameters such as salt length, memory size, and
    /// parallelism. Cannot be null.</param>
    /// <returns>A string representation of the hashed password encoded using the Argon2id algorithm.</returns>
    public static string HashPassword(string password, AppConfig config)
    {
        // Generate a secure random salt
        byte[] salt = new byte[config.Argon2SaltLength];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(salt);

        return Argon2HashEncodedToString(
            Argon2Algorithm.Argon2id,
            (uint)config.Argon2Time,
            (uint)config.Argon2Memory,
            (uint)config.Argon2Parallelism,
            Encoding.UTF8.GetBytes(password),
            salt,
            config.Argon2HashLength
        );
    }

    /// <summary>
    /// Authenticates a user based on the provided username and password.
    /// </summary>
    /// <remarks>This method performs authentication by verifying the provided username and password
    /// against stored user data. It also retrieves the user's roles as claims if authentication is
    /// successful.</remarks>
    /// <param name="username">The username of the user attempting to authenticate. Cannot be null or empty.</param>
    /// <param name="password">The password of the user attempting to authenticate. Cannot be null or empty.</param>
    /// <returns>A tuple containing the authentication result: <list type="bullet"> <item><description><c>Success</c>: <see
    /// langword="true"/> if authentication is successful; otherwise, <see langword="false"/>.</description></item>
    /// <item><description><c>UserId</c>: The unique identifier of the authenticated user, or <see langword="null"/>
    /// if authentication fails.</description></item> <item><description><c>Email</c>: The email address of the
    /// authenticated user, or <see langword="null"/> if not available or authentication fails.</description></item>
    /// <item><description><c>Claims</c>: A list of claims associated with the authenticated user, such as roles, or
    /// an empty list if authentication fails.</description></item> </list> Returns <see langword="null"/> if the
    /// user does not exist, is inactive, or the password is invalid.</returns>
    public static (bool Success, string? UserId, string? Email, List<Claim> Claims)? AuthenticateUser(string username, string password, AppConfig config)
    {
        // Get the user by username
        var user = UserStore.GetUserByUsername(username);
        
        if (user == null)
            return null;

        // Check if the user is locked out
        var lockoutUntil = UserStore.GetUserLockoutUntil(user.Id);
                
        if (lockoutUntil != DateTime.MinValue && lockoutUntil > DateTime.UtcNow)
        {
            return null;
        }

        // Reset the last login stopwatch or check key cache if not timed out
        string key = string.Empty;
        if (config.EnablePassCache)
        {
            if (_lastLogin.Elapsed > TimeSpan.FromSeconds(config.PassCacheDuration))
                RegeneratePepperAndClearCache();
            else
            {
                key = GetPassCacheKey(user.Id, password);
                _passwordCache.TryGetValue(key, out bool isValid);

                if (isValid)
                    return (true, user.Id, user.Email, AuthStore.GetUserClaims(user.Id));
            }

            _lastLogin.Restart();
        }

        // Verify the password using Argon2id
        var userHash = UserStore.GetUserPasswordHash(user.Id);
        var passwordBytes = Encoding.UTF8.GetBytes(password);
        if (!VerifyEncoded(Argon2Algorithm.Argon2id, userHash, passwordBytes))
        {
            RecordFailedLogin(user.Id, config);
            return null;
        }
        else
        {
            if (config.EnablePassCache)
            {
                key = GetPassCacheKey(user.Id, password);
                _passwordCache.Set(key, true, new MemoryCacheEntryOptions
                {
                    Size = 1,
                    SlidingExpiration = TimeSpan.FromSeconds(config.PassCacheDuration)
                });
            }
        }

        // Get user claims (roles & scopes)
        var claims = AuthStore.GetUserClaims(user.Id);

        return (true, user.Id, user.Email, claims);
    }

    /// <summary>
    /// Authenticates a client using its identifier and secret.
    /// </summary>
    /// <remarks>This method performs client authentication by verifying the provided client identifier and
    /// secret. It first checks if the client exists and is active, then attempts to authenticate using a cached secret.
    /// If the cached secret is unavailable or does not match, the method falls back to Argon2id hash verification.  The
    /// client secret is cached for subsequent authentication attempts, with a sliding expiration of 15
    /// minutes.</remarks>
    /// <param name="clientIdent">The unique identifier of the client to authenticate. Cannot be null or empty.</param>
    /// <param name="clientSecret">The secret associated with the client. Cannot be null or empty.</param>
    /// <param name="config">The application configuration used for authentication settings. Cannot be null.</param>
    /// <returns>The authenticated <see cref="Client"/> instance if authentication succeeds; otherwise, <see langword="null"/>.</returns>
    public static Client? AuthenticateClient(string clientIdent, string clientSecret, AppConfig config)
    {
        // Look up client in database
        var client = ClientStore.GetClientByClientIdentifier(clientIdent);
        if (client is null || !client.IsActive)
            return null;

        // Check cache
        if (_clientSecretCache.TryGetValue(clientIdent, out var cachedSecret))
        {
            if (cachedSecret is not null && (string)cachedSecret == clientSecret)
                return client;
            else
                return null;
        }

        // Fall back to full Argon2id verification
        if (VerifyEncoded(Argon2Algorithm.Argon2id, client.ClientSecretHash, Encoding.UTF8.GetBytes(clientSecret)))
        {
            _clientSecretCache.Set(clientIdent, clientSecret, new MemoryCacheEntryOptions
            {
                Size = 1,
                SlidingExpiration = TimeSpan.FromMinutes(15)
            });

            return client;
        }

        return null;
    }

    /// <summary>
    /// Initiates the PKCE (Proof Key for Code Exchange) authorization process by validating the input parameters and
    /// creating an authorization session.
    /// </summary>
    /// <remarks>This method validates the provided PKCE authorization parameters, ensuring that required
    /// fields such as  <c>client_id</c>, <c>redirect_uri</c>, <c>code_challenge</c>, and <c>code_challenge_method</c>
    /// are not null or empty. It also checks the validity of the <c>redirect_uri</c> for the given <c>client_id</c>. If
    /// the <c>scope</c> includes  "openid", the <c>nonce</c> parameter must also be provided.  Upon successful
    /// validation, an authorization session is created and stored, and a response containing the session  details is
    /// returned. If any validation fails or an exception occurs, an error result is returned.</remarks>
    /// <param name="form">The form collection containing the authorization request parameters, such as <c>client_id</c>, 
    /// <c>redirect_uri</c>, <c>code_challenge</c>, <c>code_challenge_method</c>, <c>scope</c>, <c>nonce</c>, and
    /// <c>state</c>.</param>
    /// <param name="config">The application configuration settings used to validate and process the authorization request.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="PkceAuthorizeResponse"/> object if the authorization
    /// session  is successfully created, or an error result with an appropriate status code if the request is invalid
    /// or fails.</returns>
    public static ApiResult<PkceAuthorizeResponse> BeginPkceAuthorization(IFormCollection form, AppConfig config)
    {
        try
        {
            var clientId = form["client_id"].ToString();
            var redirectUri = form["redirect_uri"].ToString();
            var codeChallenge = form["code_challenge"].ToString();
            var codeChallengeMethod = form["code_challenge_method"].ToString();
            var scope = form["scope"].ToString();
            var nonce = form["nonce"].ToString();
            var state = form["state"].ToString();

            if (string.IsNullOrWhiteSpace(clientId) ||
                string.IsNullOrWhiteSpace(redirectUri) ||
                string.IsNullOrWhiteSpace(codeChallenge) ||
                string.IsNullOrWhiteSpace(codeChallengeMethod))
            {
                return ApiResult<PkceAuthorizeResponse>.Fail("Invalid credentials", 400);
            }

            if (!AuthStore.IsRedirectUriValid(clientId, redirectUri))
            {
                return ApiResult<PkceAuthorizeResponse>.Fail("Invalid credentials", 400);
            }

            if (!string.IsNullOrWhiteSpace(scope) && scope.Contains("openid") && string.IsNullOrWhiteSpace(nonce))
            {
                return ApiResult<PkceAuthorizeResponse>.Fail("Invalid credentials", 400);
            }

            var jti = Utils.GenerateBase64EncodedRandomBytes(16);

            var session = new AuthSessionDto
            {
                Jti = jti,
                ClientId = ClientStore.GetClientIdByIdentifier(clientId)!,
                RedirectUri = redirectUri,
                Nonce = string.IsNullOrWhiteSpace(nonce) ? null : nonce,
                Scope = string.IsNullOrWhiteSpace(scope) ? null : scope,
                State = string.IsNullOrWhiteSpace(state) ? null : state,
                TotpRequired = false, // determined after username/password verification
                CodeChallenge = codeChallenge,
                CodeChallengeMethod = codeChallengeMethod,
                CreatedAtUtc = DateTime.UtcNow,
                ExpiresAtUtc = DateTime.UtcNow.AddMinutes(5),
                LoginMethod = null
            };

            AuthSessionStore.Insert(session);

            var response = new PkceAuthorizeResponse(
                Jti: session.Jti,
                ClientId: clientId,
                RedirectUri: session.RedirectUri,
                RequiresTotp: session.TotpRequired
            );

            return ApiResult<PkceAuthorizeResponse>.Ok(response);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Error during PKCE authorization");
            return ApiResult<PkceAuthorizeResponse>.Fail("Internal server error", 500);
        }
    }

    /// <summary>
    /// Retrieves an authentication session based on the provided JWT identifier (jti).
    /// </summary>
    /// <remarks>This method checks the validity of the provided <paramref name="jti"/> and retrieves the
    /// corresponding authentication session from the session store. If the session is expired or not found, an
    /// appropriate result is returned.</remarks>
    /// <param name="jti">The unique identifier of the JSON Web Token (JWT) associated with the authentication session. Must not be null,
    /// empty, or consist solely of whitespace.</param>
    /// <returns>An <see cref="ApiResult{AuthSessionDto}"/> containing the authentication session data if found and valid.
    /// Returns a failure result if the <paramref name="jti"/> is invalid, or a "not found" result if the session does
    /// not exist or has expired.</returns>
    public static ApiResult<AuthSessionDto> GetAuthSession(string jti)
    {
        if (string.IsNullOrWhiteSpace(jti))
            return ApiResult<AuthSessionDto>.Fail("Missing jti", 400);

        var session = AuthSessionStore.Get(jti);
        if (session is null || session.ExpiresAtUtc < DateTime.UtcNow)
            return ApiResult<AuthSessionDto>.NotFound("Session not found or expired");

        return ApiResult<AuthSessionDto>.Ok(session);
    }

    /// <summary>
    /// Handles a PKCE-based password login request, verifying user credentials and session validity.
    /// </summary>
    /// <remarks>This method validates the provided form data, checks the session's validity, and
    /// authenticates the user. If the login is successful, it attaches the user ID and TOTP requirement flag to the
    /// session. The method returns a success or failure response based on the outcome of the login process.</remarks>
    /// <param name="form">The form collection containing login data, including <c>username</c>, <c>password</c>, <c>jti</c>, and
    /// <c>redirect_uri</c>.</param>
    /// <param name="config">The application configuration settings, used to determine authentication behavior such as OTP requirements.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/> that indicates the success or failure
    /// of the login. If successful, the response includes a message indicating whether TOTP is required. If
    /// unsuccessful, the response includes an error message and an appropriate HTTP status code.</returns>
    public static ApiResult<PkceAuthorizeResponse> HandlePkcePasswordLogin(IFormCollection form, AppConfig config)
    {
        var username = form["username"];
        var password = form["password"];
        var jti = form["jti"];
        var redirectUri = form["redirect_uri"];

        if (string.IsNullOrWhiteSpace(username) ||
            string.IsNullOrWhiteSpace(password) ||
            string.IsNullOrWhiteSpace(jti) ||
            string.IsNullOrWhiteSpace(redirectUri))
        {
            return ApiResult<PkceAuthorizeResponse>.Fail("Missing required fields", 400);
        }

        var session = AuthSessionStore.Get(jti);
        if (session is null || session.ExpiresAtUtc < DateTime.UtcNow)
            return ApiResult<PkceAuthorizeResponse>.Fail("Invalid credentials", 400);

        var clientIdentifier = ClientStore.GetClientIdentifierById(session.ClientId);
        if (clientIdentifier is null)
            return ApiResult<PkceAuthorizeResponse>.Fail("Invalid credentials", 400);

        if (!AuthStore.IsRedirectUriValid(clientIdentifier!, redirectUri))
            return ApiResult<PkceAuthorizeResponse>.Fail("Invalid credentials", 400);

        var auth = AuthenticateUser(username, password, config);
        if (auth is not { Success: true })
        {
            Log.Warning("Failed login attempt for {Username}", username);
            return ApiResult<PkceAuthorizeResponse>.Fail("Invalid credentials", 400);
        }

        var userId = auth.Value.UserId;
        if (string.IsNullOrWhiteSpace(userId))
            return ApiResult<PkceAuthorizeResponse>.Fail("Invalid credentials", 400);

        var requiresTotp = false;
        var clientTotpEnabled = ClientFeaturesService.IsFeatureEnabled(clientIdentifier!, ClientFeatures.Flags.EnableTotp);
        if (clientTotpEnabled is true && UserStore.IsTotpEnabledForUserId(userId, session.ClientId))
            requiresTotp = true;

        AuthSessionStore.AttachUserIdAndTotpFlag(jti, userId, requiresTotp);
        // persist login type for AMR claim
        AuthSessionStore.AttachLoginMethod(jti, "pwd");

        return ApiResult<PkceAuthorizeResponse>.Ok(new PkceAuthorizeResponse(
            Jti: jti,
            ClientId: clientIdentifier,
            RedirectUri: session.RedirectUri ?? redirectUri,
            RequiresTotp: requiresTotp
        ));
    }

    /// <summary>
    /// Handles the PKCE (Proof Key for Code Exchange) login process with TOTP (Time-based One-Time Password)
    /// validation.
    /// </summary>
    /// <remarks>This method validates the provided form data, including the session identifier (jti), TOTP
    /// code, and redirect URI. It ensures the session is valid, not expired, and properly configured for TOTP-based
    /// authentication. If the validation succeeds, it returns an authorization response containing session
    /// details.</remarks>
    /// <param name="form">The form collection containing the required fields: <c>jti</c>, <c>totp_code</c>, and <c>redirect_uri</c>.</param>
    /// <param name="config">The application configuration used for verifying the TOTP code.</param>
    /// <returns>An <see cref="ApiResult{PkceAuthorizeResponse}"/> containing the authorization response if the login is
    /// successful. If validation fails, the result contains an error message and the appropriate HTTP status code.</returns>
    public static ApiResult<PkceAuthorizeResponse> HandlePkceTotpLogin(IFormCollection form, AppConfig config)
    {
        var jti = form["jti"];
        var totp = form["totp_code"];
        var redirectUri = form["redirect_uri"];

        if (string.IsNullOrWhiteSpace(jti) ||
            string.IsNullOrWhiteSpace(totp) ||
            string.IsNullOrWhiteSpace(redirectUri))
        {
            return ApiResult<PkceAuthorizeResponse>.Fail("Invalid credentials", 400);
        }

        var session = AuthSessionStore.Get(jti);
        if (session is null || session.ExpiresAtUtc < DateTime.UtcNow)
            return ApiResult<PkceAuthorizeResponse>.Fail("Invalid credentials", 400);

        var clientIdentifier = ClientStore.GetClientIdentifierById(session.ClientId);
        if (string.IsNullOrWhiteSpace(clientIdentifier))
            return ApiResult<PkceAuthorizeResponse>.Fail("Invalid credentials", 400);

        if (!AuthStore.IsRedirectUriValid(clientIdentifier, redirectUri))
            return ApiResult<PkceAuthorizeResponse>.Fail("Invalid credentials", 400);

        if (!session.TotpRequired)
            return ApiResult<PkceAuthorizeResponse>.Fail("Invalid credentials", 400);

        if (string.IsNullOrWhiteSpace(session.UserId) ||
            string.IsNullOrWhiteSpace(session.RedirectUri))
            return ApiResult<PkceAuthorizeResponse>.Fail("Malformed session", 500);

        var result = UserService.VerifyTotpCode(session.UserId, session.ClientId, totp, config);
        if (!result.Success)
            return ApiResult<PkceAuthorizeResponse>.Fail("Invalid credentials", 400);

        // persist login type for AMR claim
        AuthSessionStore.AttachLoginMethod(session.Jti, "otp");

        return ApiResult<PkceAuthorizeResponse>.Ok(new PkceAuthorizeResponse(
            Jti: session.Jti,
            ClientId: clientIdentifier,
            RedirectUri: session.RedirectUri!,
            RequiresTotp: false
        ));
    }


    /// <summary>
    /// Finalizes the PKCE login process by validating the session and generating a PKCE code.
    /// </summary>
    /// <remarks>This method validates the provided session ID (jti) and ensures that the session exists, is
    /// not expired, and has an authenticated user. It also verifies the validity of the redirect URI associated with
    /// the client. If all validations pass, a PKCE code is generated and stored for subsequent use in the authorization
    /// flow.</remarks>
    /// <param name="form">The form collection containing the session ID (jti) and other relevant data.</param>
    /// <param name="config">The application configuration used for the operation.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/> with the generated PKCE code if the
    /// operation succeeds. If the operation fails, the result contains an error message and an HTTP status code.</returns>

    public static IResult FinalizePkceLogin(IFormCollection form, AppConfig config)
    {
        var jti = form["jti"];
        if (string.IsNullOrWhiteSpace(jti))
            return Results.BadRequest("Invalid credentials");

        // extract and validate jti, client_id, redirect_uri
        var session = AuthSessionStore.Consume(jti);
        if (session == null || session.ExpiresAtUtc < DateTime.UtcNow)
            return Results.BadRequest("Invalid credentials");

        var clientIdentifier = ClientStore.GetClientIdentifierById(session.ClientId);
        if (clientIdentifier is null)
            return Results.BadRequest("Invalid client");

        if (!AuthStore.IsRedirectUriValid(clientIdentifier, session.RedirectUri))
            return Results.BadRequest("Invalid credentials");

        // generate code and store pkce code
        var code = Utils.GenerateBase64EncodedRandomBytes(32);
        var expiresAt = DateTime.UtcNow.AddSeconds(config.PkceCodeLifetime);

        AuthStore.StorePkceCode(new PkceCode
        {
            Code = code,
            ClientIdentifier = clientIdentifier,
            RedirectUri = session.RedirectUri!,
            CodeChallenge = session.CodeChallenge!,
            CodeChallengeMethod = session.CodeChallengeMethod!,
            ExpiresAt = expiresAt,
            IsUsed = false,
            UserId = session.UserId!,
            Jti = session.Jti,
            Nonce = session.Nonce,
            Scope = session.Scope,
            LoginMethod = session.LoginMethod
        });

        // build redirect_uri?code=...&state=...
        var uri = new UriBuilder(session.RedirectUri!);
        var query = QueryHelpers.ParseQuery(uri.Query);
        query["code"] = code;
        if (!string.IsNullOrWhiteSpace(session.State))
            query["state"] = session.State;

        var rebuilt = new QueryBuilder(query.SelectMany(kvp => kvp.Value.Select(v => new KeyValuePair<string, string>(kvp.Key, v))));
        uri.Query = rebuilt.ToQueryString().Value;

        // final redirect
        return Results.Redirect(uri.ToString());
    }

    /// <summary>
    /// Exchanges a PKCE authorization code for an access token and optional ID token.
    /// </summary>
    /// <remarks>This method validates the provided PKCE authorization code, client identifier, code verifier,
    /// and redirect URI. If the validation succeeds, it issues an access token and optionally an ID token based on the
    /// requested scope. The method also supports generating a refresh token if token refresh is enabled in the
    /// configuration.</remarks>
    /// <param name="form">The form collection containing the PKCE exchange parameters, including <c>code</c>, <c>client_id</c>,
    /// <c>code_verifier</c>, and <c>redirect_uri</c>.</param>
    /// <param name="config">The application configuration settings, which determine PKCE and token refresh behavior.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="TokenResponse"/> object with the issued tokens if the
    /// exchange is successful. If the exchange fails, an error result is returned indicating the reason for failure.</returns>
    public static ApiResult<TokenResponse> ExchangePkceCode(IFormCollection form, AppConfig config)
    {
        if (!config.EnablePkce)
            return OidcErrors.InvalidGrant<TokenResponse>();

        var code = form["code"].ToString();
        var clientId = form["client_id"].ToString();
        var codeVerifier = form["code_verifier"].ToString();
        var redirectUri = form["redirect_uri"].ToString();

        if (string.IsNullOrWhiteSpace(code) ||
            string.IsNullOrWhiteSpace(clientId) ||
            string.IsNullOrWhiteSpace(codeVerifier) ||
            string.IsNullOrWhiteSpace(redirectUri))
        {
            Log.Warning("PKCE exchange failed: missing required fields. client_id={ClientId}, redirect_uri={RedirectUri}", clientId, redirectUri);
            return OidcErrors.InvalidRequest<TokenResponse>("Missing required fields");
        }

        var pkce = AuthStore.GetPkceCode(code);
        if (pkce is null || pkce.IsUsed || pkce.ExpiresAt < DateTime.UtcNow)
        {
            Log.Warning("PKCE exchange failed: code invalid/used/expired. client_id={ClientId}, code={Code}", clientId, code);
            return OidcErrors.InvalidGrant<TokenResponse>();
        }

        if (!string.Equals(pkce.ClientIdentifier, clientId, StringComparison.Ordinal) ||
            !string.Equals(pkce.RedirectUri, redirectUri, StringComparison.Ordinal))
        {
            Log.Warning("PKCE exchange failed: client_id or redirect_uri mismatch. client_id={ClientId}, expected_client_id={Expected}, redirect_uri={RedirectUri}, expected_redirect_uri={ExpectedUri}",
                clientId, pkce.ClientIdentifier, redirectUri, pkce.RedirectUri);
            return OidcErrors.InvalidGrant<TokenResponse>();
        }

        var challengeValid = pkce.CodeChallengeMethod.ToLowerInvariant() switch
        {
            "plain" => pkce.CodeChallenge == codeVerifier,
            "s256" => pkce.CodeChallenge == Utils.ComputeS256Challenge(codeVerifier),
            _ => false
        };

        if (!challengeValid)
        {
            Log.Warning("PKCE exchange failed: code_verifier mismatch. client_id={ClientId}, method={Method}", clientId, pkce.CodeChallengeMethod);
            return OidcErrors.InvalidGrant<TokenResponse>();
        }

        AuthStore.MarkPkceCodeAsUsed(code);

        if (string.IsNullOrWhiteSpace(pkce.UserId))
        {
            Log.Warning("PKCE exchange failed: no user associated with code. client_id={ClientId}, code={Code}", clientId, code);
            return OidcErrors.InvalidGrant<TokenResponse>();
        }

        var user = UserStore.GetUserById(pkce.UserId);
        if (user is null)
        {
            Log.Warning("PKCE exchange failed: user not found. user_id={UserId}", pkce.UserId);
            return OidcErrors.InvalidGrant<TokenResponse>();
        }

        var actualClientId = ClientStore.GetClientIdByIdentifier(clientId);
        if (actualClientId is null)
        {
            Log.Warning("PKCE exchange failed: client_id not found. client_id={ClientId}", clientId);
            return OidcErrors.InvalidGrant<TokenResponse>();
        }

        var claims = AuthStore.GetUserClaims(pkce.UserId);
        claims.Add(new Claim("client_id", pkce.ClientIdentifier));

        if (!string.IsNullOrWhiteSpace(pkce.Scope))
        {
            claims.Add(new Claim("scope", pkce.Scope));
        }

        var issueIdToken = pkce.Scope?.Contains("openid") == true;

        if (issueIdToken)
        {
            if (!string.IsNullOrWhiteSpace(pkce.Nonce))
            {
                if (!AuthStore.InsertNonce(user.Id, actualClientId, pkce.Nonce))
                {
                    Log.Warning("PKCE exchange failed: nonce reused. user={UserId}, client={ClientId}, nonce={Nonce}", user.Id, actualClientId, pkce.Nonce);
                    return OidcErrors.InvalidGrant<TokenResponse>();
                }
            }
            else
            {
                Log.Warning("PKCE exchange failed: nonce required for openid scope but not provided.");
                return OidcErrors.InvalidGrant<TokenResponse>();
            }
        }

        var audience = ClientStore.GetClientAudienceByIdentifier(pkce.ClientIdentifier);
        var tokenInfo = TokenIssuer.IssueToken(config, claims, isAdmin: false, clientId: actualClientId, audience: audience);
        UserService.WriteSessionToDb(tokenInfo, config, pkce.ClientIdentifier, pkce.LoginMethod!);

        string? refreshToken = null;
        if (config.EnableTokenRefresh)
        {
            refreshToken = UserService.GenerateAndStoreRefreshToken(
                config, pkce.UserId, tokenInfo.Jti, pkce.ClientIdentifier, issueIdToken);
        }

        string? idToken = null;
        if (issueIdToken)
        {
            idToken = TokenIssuer.IssueIdToken(config, claims, pkce.ClientIdentifier, pkce.LoginMethod, pkce.Nonce);
        }

        AuthStore.AttachJtiToPkceCode(code, tokenInfo.Jti);

        Log.Debug("PKCE exchange successful. client_id={ClientId}, user_id={UserId}, jti={Jti}", clientId, pkce.UserId, tokenInfo.Jti);

        return ApiResult<TokenResponse>.Ok(new TokenResponse
        {
            AccessToken = tokenInfo.Token,
            TokenType = "bearer",
            ExpiresIn = (int)(tokenInfo.ExpiresAt - tokenInfo.IssuedAt).TotalSeconds,
            Jti = tokenInfo.Jti,
            RefreshToken = refreshToken,
            Audience = audience,
            IdToken = idToken
        });
    }

    /// <summary>
    /// <summary>
    /// Issues an administrative access token for a user with valid credentials and the required admin role.
    /// </summary>
    /// <remarks>This method authenticates the user using the provided credentials and checks if the user has
    /// the "MadAdmin" role. If the user is authenticated and authorized, an administrative token is issued. The token
    /// includes claims for the user's identity and roles. The method also logs the token issuance and writes the
    /// session to the database.</remarks>
    /// <param name="req">The token request containing the username, password, and optional client identifier.</param>
    /// <param name="config">The application configuration used for token generation and authentication.</param>
    /// <param name="ip">The IP address of the client making the request.</param>
    /// <param name="ua">The user agent string of the client making the request.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="TokenResponse"/> if the request is successful.  Returns a
    /// forbidden result if the credentials are invalid or the user does not have the required admin role.</returns>
    public static ApiResult<TokenResponse> IssueAdminToken(
        TokenRequest req,
        AppConfig config,
        string ip,
        string ua)
    {
        if (string.IsNullOrWhiteSpace(req.Username) || string.IsNullOrWhiteSpace(req.Password))
        {
            Log.Warning("Token request failed: missing username or password: {Username} IP {IP} UA {UA}", req.Username, ip, ua);
            return ApiResult<TokenResponse>.Forbidden("Invalid credentials");
        }

        var result = AuthenticateUser(req.Username, req.Password, config);
        if (result is not { Success: true } r)
        {
            Log.Warning("Failed login attempt for {Username} from IP {IP} UA {UA}", req.Username, ip, ua);
            return ApiResult<TokenResponse>.Forbidden("Invalid credentials");
        }

        // Check admin role
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, r.UserId!),
            new(JwtRegisteredClaimNames.Email, r.Email ?? "")
        };
        claims.AddRange(r.Claims);

        bool isAdmin = r.Claims.Any(c => c.Value == Constants.MadAdmin);
        if (!isAdmin)
        {
            Log.Warning("Non-admin user {UserId} attempted to access admin token endpoint", r.UserId);
            return ApiResult<TokenResponse>.Forbidden("Invalid credentials");
        }

        var tokenInfo = TokenIssuer.IssueToken(config, claims, isAdmin: true, "admin");

        UserService.WriteSessionToDb(tokenInfo, config, req.ClientIdentifier ?? "admin", "pwd");

        Log.Information("Admin Token issued for user {UserId}", r.UserId);

        if (config.EnableAuditLogging)
            Utils.Audit.Logg(
                action: "admin_token_issued",
                target: req.ClientIdentifier ?? "(no client id)"
            );

        return ApiResult<TokenResponse>.Ok(new TokenResponse
        {
            AccessToken = tokenInfo.Token,
            ExpiresIn = (int)(tokenInfo.ExpiresAt - tokenInfo.IssuedAt).TotalSeconds,
            Jti = tokenInfo.Jti
        });
    }

    /// <summary>
    /// Issues a user access token based on the provided credentials and client information.
    /// </summary>
    /// <remarks>This method validates the provided credentials and client identifier, authenticates the user,
    /// and issues a JWT access token. If token refresh is enabled in the configuration, a refresh token is also
    /// generated and stored. The method logs audit information and warnings for failed attempts or invalid
    /// inputs.</remarks>
    /// <param name="req">The token request containing the username, password, and client identifier.</param>
    /// <param name="config">The application configuration used for token generation and validation.</param>
    /// <param name="ip">The IP address of the client making the request.</param>
    /// <param name="userAgent">The user agent string of the client making the request.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="TokenResponse"/> if the request is successful. Returns a
    /// forbidden result if the credentials or client information are invalid.</returns>
    public static ApiResult<TokenResponse> IssueUserToken(
        IFormCollection form,
        AppConfig config,
        string ip,
        string userAgent)
    {
        var username = form["username"].ToString().Trim();
        var password = form["password"].ToString().Trim();
        var clientIdent = form["client_id"].ToString().Trim();
        var clientSecret = form["client_secret"].ToString().Trim();

        if (string.IsNullOrWhiteSpace(username) ||
            string.IsNullOrWhiteSpace(password) ||
            string.IsNullOrWhiteSpace(clientIdent) ||
            string.IsNullOrWhiteSpace(clientSecret))
            return OidcErrors.InvalidRequest<TokenResponse>("Missing required fields");

        if (!ValidateOidcClient(clientIdent, clientSecret, config))
        {
            Log.Warning("Client authentication failed for {ClientId}. IP {IP} UA {UA}", clientIdent, ip, userAgent);
            return OidcErrors.InvalidClient<TokenResponse>();
        }

        try
        {
            var audience = ClientStore.GetClientAudienceByIdentifier(clientIdent);
            var actualClientId = ClientStore.GetClientIdByIdentifier(clientIdent);

            if (string.IsNullOrWhiteSpace(audience))
            {
                Log.Warning("Client identifier not found or missing audience: {ClientId}", clientIdent);
                return OidcErrors.InvalidClient<TokenResponse>();
            }

            var result = AuthenticateUser(username, password, config);
            if (result is not { Success: true } r)
            {
                Log.Warning("Failed login attempt for {Username}. IP {IP} UA {UA}", username, ip, userAgent);
                return OidcErrors.InvalidGrant<TokenResponse>();
            }

            var requiresTotp = UserStore.IsTotpEnabledForUserId(r.UserId!, actualClientId);
            if (requiresTotp)
            {
                var totpCode = form["totp_code"].ToString();
                if (string.IsNullOrWhiteSpace(totpCode) || !ValidateTotpCode(r.UserId!, actualClientId, totpCode))
                {
                    Log.Warning("TOTP required and failed for user {UserId}", r.UserId);
                    return OidcErrors.InvalidGrant<TokenResponse>();
                }
            }

            // Unified claim building
            var claims = AuthStore.GetUserClaims(r.UserId!);
            claims.Add(new Claim("client_id", clientIdent));

            // Extract scope values for downstream logic
            var scopeValues = claims
                .Where(c => c.Type == "scope")
                .Select(c => c.Value)
                .Distinct()
                .ToList();

            if (scopeValues.Any())
                claims.Add(new Claim("scope", string.Join(' ', scopeValues)));

            var tokenInfo = TokenIssuer.IssueToken(config, claims, isAdmin: false, clientId: actualClientId, audience: audience);
            UserService.WriteSessionToDb(tokenInfo, config, clientIdent, "pwd");

            var issueIdToken = scopeValues.Contains("openid");

            string? refreshToken = null;
            if (config.EnableTokenRefresh)
            {
                refreshToken = UserService.GenerateAndStoreRefreshToken(
                    config, tokenInfo.UserId, tokenInfo.Jti, clientIdent, issueIdToken);
            }

            string? idToken = null;
            if (issueIdToken)
            {
                idToken = TokenIssuer.IssueIdToken(config, claims, clientIdent, "pwd");
            }

            Log.Debug("Issued token for user {UserId} under client {ClientIdent}", r.UserId, clientIdent);

            return ApiResult<TokenResponse>.Ok(new TokenResponse
            {
                AccessToken = tokenInfo.Token,
                TokenType = "bearer",
                ExpiresIn = (int)(tokenInfo.ExpiresAt - tokenInfo.IssuedAt).TotalSeconds,
                Jti = tokenInfo.Jti,
                RefreshToken = refreshToken,
                Audience = audience,
                IdToken = idToken
            });
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Error issuing user token for {Username}", username);
            return ApiResult<TokenResponse>.Fail("Internal server error", 500);
        }
    }



    /// <summary>
    /// Refreshes the access token using the provided refresh token and application configuration.
    /// </summary>
    /// <remarks>This method validates the provided refresh token, revokes the old token, and issues a new
    /// access token  along with a new refresh token. The caller must ensure that the refresh token is valid and has not
    /// been  tampered with. If the refresh token is invalid, expired, or revoked, the method returns an error
    /// result.</remarks>
    /// <param name="req">The request containing the refresh token and other required information.</param>
    /// <param name="config">The application configuration used to issue the new access token.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="TokenResponse"/> with the new access token,  or an error
    /// result if the refresh token is invalid, expired, or revoked.</returns>
    public static ApiResult<TokenResponse> RefreshAccessToken(IFormCollection form, AppConfig config)
    {
        if (!config.EnableTokenRefresh)
            return ApiResult<TokenResponse>.Fail("Invalid request", 400);

        try
        {
            var raw = form["refresh_token"].ToString();
            var clientId = form["client_id"].ToString();
            var clientSecret = form["client_secret"].ToString();

            if (string.IsNullOrWhiteSpace(raw) ||
                string.IsNullOrWhiteSpace(clientId) ||
                string.IsNullOrWhiteSpace(clientSecret))
                return OidcErrors.InvalidRequest<TokenResponse>("Missing required fields");

            if (!ValidateOidcClient(clientId, clientSecret, config))
            {
                Log.Warning("Refresh token request failed client validation: {ClientId}", clientId);
                return OidcErrors.InvalidClient<TokenResponse>();
            }

            var sha256 = Utils.Sha256Base64(raw);
            var tokenRow = UserStore.GetRefreshTokenBySha256Hash(sha256);

            if (tokenRow is null || tokenRow.IsRevoked || tokenRow.ExpiresAt < DateTime.UtcNow)
            {
                Log.Warning("Refresh token invalid or expired for client {ClientId}", clientId);
                return OidcErrors.InvalidGrant<TokenResponse>();
            }

            UserStore.RevokeRefreshToken(tokenRow.Id);

            var claims = AuthStore.GetUserClaims(tokenRow.UserId);

            var scopeValues = claims
                .Where(c => c.Type == "scope")
                .Select(c => c.Value)
                .Distinct()
                .ToList();

            if (scopeValues.Any())
                claims.Add(new Claim("scope", string.Join(' ', scopeValues)));

            claims.Add(new Claim("client_id", tokenRow.ClientIdentifier));

            var audience = ClientStore.GetClientAudienceByIdentifier(tokenRow.ClientIdentifier);

            var actualClientId = ClientStore.GetClientIdByIdentifier(tokenRow.ClientIdentifier);
            var tokenInfo = TokenIssuer.IssueToken(config, claims, isAdmin: false, clientId: actualClientId!, audience: audience);
            UserService.WriteSessionToDb(tokenInfo, config, tokenRow.ClientIdentifier, "refresh");

            var newRefreshToken = UserService.GenerateAndStoreRefreshToken(
                config,
                tokenRow.UserId,
                tokenInfo.Jti,
                tokenRow.ClientIdentifier,
                tokenRow.IsOpenIdToken
            );

            if (config.EnableAuditLogging)
            {
                Utils.Audit.Logg(
                    action: "refresh_token_used",
                    target: tokenRow.ClientIdentifier
                );
            }

            string? idToken = null;
            if (tokenRow.IsOpenIdToken)
            {
                idToken = TokenIssuer.IssueIdToken(config, claims, tokenRow.ClientIdentifier, "refresh");
            }

            return ApiResult<TokenResponse>.Ok(new TokenResponse
            {
                AccessToken = tokenInfo.Token,
                TokenType = "bearer",
                ExpiresIn = (int)(tokenInfo.ExpiresAt - tokenInfo.IssuedAt).TotalSeconds,
                Jti = tokenInfo.Jti,
                RefreshToken = newRefreshToken,
                Audience = audience,
                IdToken = idToken
            });
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Error refreshing access token");
            return ApiResult<TokenResponse>.Fail("Internal server error", 500);
        }
    }

    /// <summary>
    /// Validates the credentials of an OpenID Connect (OIDC) client.
    /// </summary>
    /// <remarks>This method verifies the provided client credentials against the stored hash in the database.
    /// The client must be active for validation to succeed.</remarks>
    /// <param name="clientId">The unique identifier of the client to validate.</param>
    /// <param name="clientSecret">The secret associated with the client, used for authentication.</param>
    /// <param name="config">The application configuration containing database connection settings.</param>
    /// <returns><see langword="true"/> if the client credentials are valid and the client is active; otherwise, <see
    /// langword="false"/>.</returns>
    public static bool ValidateOidcClient(string clientId, string clientSecret, AppConfig config)
    {
        try
        {
            // Normalize input
            var normalizedId = clientId.Trim();
            var normalizedSecret = clientSecret.Trim();

            // Check the cache first
            if (_clientSecretCache.TryGetValue(clientId, out var cachedSecret))
            {
                if (cachedSecret is not null && (string)cachedSecret == clientSecret)
                    return true;
                else
                    return false;
            }

            // Lookup hash from DB
            var clientSecretHash = ClientStore.GetClientSecretHashByIdentifier(normalizedId);
            if (string.IsNullOrEmpty(clientSecretHash))
                return false;

            // Fallback to Argon2 verification
            var verified = VerifyEncoded(
                Argon2Algorithm.Argon2id,
                clientSecretHash,
                Encoding.UTF8.GetBytes(normalizedSecret)
            );

            if (verified)
            {
                _clientSecretCache.Set(clientId, clientSecret, new MemoryCacheEntryOptions
                {
                    Size = 1,
                    SlidingExpiration = TimeSpan.FromMinutes(15)
                });
            }

            return verified;
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Error validating OIDC client {ClientId}", clientId);
            return false;
        }
    }

    /// <summary>
    /// Retrieves the expected audience value for a given client identifier.
    /// </summary>
    /// <remarks>The method queries the database to find the audience for the provided client identifier.  If
    /// no active client matches the identifier, the method returns <see langword="null"/>.</remarks>
    /// <param name="clientIdentifier">The unique identifier of the client. This value is used to query the database for the associated audience.</param>
    /// <returns>The audience associated with the specified client identifier if the client is active; otherwise, <see
    /// langword="null"/>.</returns>
    public static string? GetExpectedAudienceForClient(string clientIdentifier)
    {
        try
        {
            return ClientStore.GetClientAudienceByIdentifier(clientIdentifier);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Error retrieving audience for client {ClientIdentifier}", clientIdentifier);
            return null;
        }
    }

    /// <summary>
    /// Records a failed login attempt for the specified user and updates their account status accordingly.
    /// </summary>
    /// <remarks>This method increments the failed login attempt counter for the user and determines whether
    /// the account should be locked  based on the configured thresholds. If the time since the last failed login
    /// exceeds the reset window, the counter is reset. If the number of failed attempts exceeds the maximum allowed,
    /// the account is locked for a specified duration.</remarks>
    /// <param name="userId">The unique identifier of the user whose failed login attempt is being recorded.</param>
    /// <param name="config">The application configuration containing thresholds and durations for login failure handling.</param>
    public static void RecordFailedLogin(string userId, AppConfig config)
    {
        try
        {
            AuthStore.RecordFailedLogin(userId, config);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to record login attempt for user {UserId}", userId);
        }
    }

    /// <summary>
    /// Retrieves the number of failed login attempts for the specified user.
    /// </summary>
    /// <remarks>This method logs any errors encountered during the retrieval process and returns 0 to ensure
    /// the application flow is not disrupted.</remarks>
    /// <param name="userId">The unique identifier of the user whose failed login attempts are to be retrieved. Cannot be null or empty.</param>
    /// <returns>The number of failed login attempts for the specified user.  Returns 0 if an error occurs during the retrieval
    /// process.</returns>
    public static int GetFailedLoginAttempts(string userId)
    {
        try
        {
            return AuthStore.GetFailedLoginAttempts(userId);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to get failed login attempts for user {UserId}", userId);
            return 0; // Return 0 if there's an error to avoid breaking the flow
        }
    }

    /// <summary>
    /// Logs out a user by revoking their active session and associated refresh tokens for a specific client.
    /// </summary>
    /// <remarks>This method revokes the user's session and refresh tokens for the specified client in the
    /// database. Additionally, an audit log entry is created to record the logout action.</remarks>
    /// <param name="userId">The unique identifier of the user to log out. Cannot be <see langword="null"/> or empty.</param>
    /// <param name="clientIdentifier">The unique identifier of the client from which the user is logging out. Cannot be <see langword="null"/> or
    /// empty.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/> that confirms the logout operation. The
    /// message includes the user ID and client identifier.</returns>
    public static ApiResult<MessageResponse> Logout(string userId, string clientIdentifier, AppConfig config)
    {
        try
        {
            AuthStore.LogoutUser(userId, clientIdentifier);

            if (config.EnableAuditLogging)
                Utils.Audit.Logg(
                    action: "logout",
                    target: clientIdentifier
                );

            return ApiResult<MessageResponse>.Ok(
                new MessageResponse(true, $"User '{userId}' logged out of client '{clientIdentifier}'")
            );
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to log out user {UserId} from client {ClientIdentifier}", userId, clientIdentifier);
            return ApiResult<MessageResponse>.Fail("Internal server error", 500);
        }
    }

    /// <summary>
    /// Revokes all active sessions and refresh tokens for the specified user.
    /// </summary>
    /// <remarks>This method updates the database to mark all sessions and refresh tokens associated with the
    /// specified user as revoked. Additionally, an audit log entry is created to record the logout action.</remarks>
    /// <param name="userId">The unique identifier of the user whose sessions and refresh tokens are to be revoked. Cannot be null or empty.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/> that confirms the operation's success.
    /// The message indicates that all sessions and refresh tokens for the specified user have been revoked.</returns>
    public static ApiResult<MessageResponse> LogoutAll(string userId, AppConfig config)
    {
        try
        {
            AuthStore.LogoutUserAllClients(userId);

            if (config.EnableAuditLogging)
                Utils.Audit.Logg(
                    action: "logout_all",
                    null
                );

            return ApiResult<MessageResponse>.Ok(
                new MessageResponse(true, $"All sessions and refresh tokens revoked for user '{userId}'")
            );
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to logout of all sessions for user {UserId}", userId);
            return ApiResult<MessageResponse>.Fail("Internal server error", 500);
        }
    }

    /// <summary>
    /// Retrieves the OpenID Connect (OIDC) discovery document for the specified application configuration.
    /// </summary>
    /// <remarks>The discovery document includes information such as the issuer URL, token endpoint, JSON Web
    /// Key Set (JWKS) URI, supported response types, subject types, signing algorithms, scopes, and claims. The base
    /// URL is determined based on the <see cref="AppConfig.AuthDomainNoSSL"/> property, which specifies whether to use
    /// HTTP or HTTPS.</remarks>
    /// <param name="config">The application configuration containing the authentication domain and related settings.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing an <see cref="OidcDiscoveryResponse"/> object that provides the OIDC
    /// discovery document, including endpoints, supported algorithms, and claims.</returns>
    public static ApiResult<OidcDiscoveryResponse> GetDiscoveryDocument(AppConfig config)
    {
        var baseUrl = config.AuthDomainNoSSL ? "http://" : "https://";
        baseUrl += config.AuthDomain;

        var discovery = new OidcDiscoveryResponse
        {
            Issuer = baseUrl,
            TokenEndpoint = $"{baseUrl}/token",
            JwksUri = $"{baseUrl}/jwks.json",
            GrantTypesSupported = new[] { "authorization_code", "password", "client_credentials", "refresh_token" },
            ResponseTypesSupported = new[] { "token" },
            TokenEndpointAuthMethodsSupported = new[] { "client_secret_post", "client_secret_basic" },
            ResponseModesSupported = new[] { "fragment" },
            CodeChallengeMethodsSupported = new[] { "plain", "S256" },
            SubjectTypesSupported = new[] { "public" },
            IdTokenSigningAlgValuesSupported = new[] { "RS256", "ES256" },
            ScopesSupported = new[] { "openid", "email", "profile" },
            ClaimsSupported = new[] { "sub", "email", "jti", "iat", "exp", "aud", "iss", "token_use", "mad" },
            UserInfoEndpoint = $"{baseUrl}/userinfo",
        };

        return ApiResult<OidcDiscoveryResponse>.Ok(discovery);
    }

    /// <summary>
    /// Retrieves the JSON Web Key Set (JWKS) containing the public key used for verifying tokens.
    /// </summary>
    /// <remarks>This method generates a JWKS response based on the current public key and its associated
    /// metadata. The key is formatted as either an RSA or EC key, depending on the type of the public key in use. If
    /// the key type is unsupported or an error occurs during key export, the method returns a failure result.</remarks>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="JwksResponse"/> object with the public key details if
    /// successful, or an error message and status code if the operation fails.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the public key does not contain the necessary parameters for export.</exception>
    public static ApiResult<JwksResponse> GetJwks()
    {
        var publicKey = TokenKeyCache.GetPublicKey(isAdmin: false);
        var kid = TokenKeyCache.GetKeyId(isAdmin: false);

        try
        {
            JwkKey jwk;

            if (publicKey is RsaSecurityKey rsaKey)
            {
                var rsaParams = rsaKey.Rsa?.ExportParameters(false)
                               ?? throw new InvalidOperationException("RSA key has no parameters");

                jwk = new JwkKey
                {
                    Kid = kid ?? "",
                    Kty = "RSA",
                    Alg = "RS256",
                    Use = "sig",
                    N = Utils.Base64Url(rsaParams.Modulus!),
                    E = Utils.Base64Url(rsaParams.Exponent!),
                };
            }
            else if (publicKey is ECDsaSecurityKey ecKey)
            {
                var ecParams = ecKey.ECDsa?.ExportParameters(false)
                              ?? throw new InvalidOperationException("EC key has no parameters");

                jwk = new JwkKey
                {
                    Kid = kid ?? "",
                    Kty = "EC",
                    Alg = "ES256",
                    Use = "sig",
                    Crv = "P-256",
                    X = Utils.Base64Url(ecParams.Q.X!),
                    Y = Utils.Base64Url(ecParams.Q.Y!),
                    N = "",
                    E = ""
                };
            }
            else
            {
                return ApiResult<JwksResponse>.Fail("Unsupported key type", 500);
            }

            var response = new JwksResponse
            {
                Keys = new List<JwkKey> { jwk }
            };

            return ApiResult<JwksResponse>.Ok(response);
        }
        catch (Exception ex)
        {
            return ApiResult<JwksResponse>.Fail("Unable to export public key: " + ex.Message, 500);
        }
    }

    /// <summary>
    /// Issues an OpenID Connect (OIDC) token using the client credentials grant type.
    /// </summary>
    /// <remarks>This method supports only the <c>client_credentials</c> grant type. The client must provide
    /// valid credentials (<c>client_id</c> and <c>client_secret</c>) to obtain a token. The issued token includes
    /// claims for the client and any associated active scopes.</remarks>
    /// <param name="form">The form collection containing the request parameters, including <c>grant_type</c>, <c>client_id</c>, and
    /// <c>client_secret</c>.</param>
    /// <param name="config">The application configuration used for token issuance and client validation.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="TokenResponse"/> with the issued token details if the
    /// request is valid. Returns an error result if the request is invalid, such as unsupported grant type, missing or
    /// invalid client credentials.</returns>
    public static ApiResult<TokenResponse> IssueOidcToken(Microsoft.AspNetCore.Http.IFormCollection form, AppConfig config)
    {
        var grantType = form["grant_type"].ToString();
        var clientId = form["client_id"].ToString();
        var clientSecret = form["client_secret"].ToString();

        if (string.IsNullOrWhiteSpace(grantType) || grantType != "client_credentials")
            return ApiResult<TokenResponse>.Fail("Invalid credentials", 403);

        if (string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(clientSecret))
            return ApiResult<TokenResponse>.Fail("Invalid credentials", 403);

        try
        {
            if (!ValidateOidcClient(clientId, clientSecret, config))
                return ApiResult<TokenResponse>.Fail("Invalid credentials", 403);

            var scopes = ClientStore.GetClientScopes(clientId);

            var claims = new List<Claim>
            {
                new(JwtRegisteredClaimNames.Sub, clientId),
                new("client_id", clientId),
                new("token_use", "access")
            };

            if (scopes.Count > 0)
                claims.Add(new Claim("scope", string.Join(' ', scopes)));

            var audience = ClientStore.GetClientAudienceByIdentifier(clientId);

            var actualClientId = ClientStore.GetClientIdByIdentifier(clientId);
            var tokenInfo = TokenIssuer.IssueToken(config, claims, isAdmin: false, clientId: actualClientId!, audience: audience);

            var response = new TokenResponse
            {
                AccessToken = tokenInfo.Token,
                TokenType = "bearer",
                ExpiresIn = (int)(tokenInfo.ExpiresAt - tokenInfo.IssuedAt).TotalSeconds,
                Jti = tokenInfo.Jti,
                Audience = audience
            };

            if (config.EnableAuditLogging)
                Utils.Audit.Logg(
                    action: "oidc_token_issued",
                    target: clientId
                );

            return ApiResult<TokenResponse>.Ok(response);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Error issuing OIDC token for client {ClientId}", clientId);
            return ApiResult<TokenResponse>.Fail("Internal server error", 500);
        }
    }

    /// <summary>
    /// Validates and introspects a JSON Web Token (JWT) to extract its claims and metadata.
    /// </summary>
    /// <remarks>This method validates the token using the provided configuration, including issuer
    /// validation,  lifetime validation, and signature validation. If the token is valid, its claims and metadata  are
    /// extracted into a dictionary. If the token is invalid or an error occurs during validation,  the method returns a
    /// dictionary indicating that the token is inactive.</remarks>
    /// <param name="token">The JWT to be introspected. Must be a valid, readable token.</param>
    /// <param name="config">The application configuration containing validation parameters, such as the issuer and signing key.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a dictionary of token claims and metadata.  The dictionary includes the
    /// following keys: <list type="bullet"> <item><description><c>"active"</c>: A boolean indicating whether the token
    /// is valid and active.</description></item> <item><description><c>"iss"</c>: The issuer of the
    /// token.</description></item> <item><description><c>"sub"</c>: The subject of the token.</description></item>
    /// <item><description><c>"exp"</c>: The expiration time of the token, in seconds since the
    /// epoch.</description></item> <item><description><c>"iat"</c>: The issued-at time of the token, in seconds since
    /// the epoch.</description></item> <item><description><c>"nbf"</c>: The not-before time of the token, in seconds
    /// since the epoch.</description></item> <item><description><c>"aud"</c>: The audience of the
    /// token.</description></item> <item><description><c>"scope"</c>: An array of scopes associated with the
    /// token.</description></item> <item><description><c>"client_id"</c>: The client identifier associated with the
    /// token.</description></item> <item><description><c>"username"</c>: The username associated with the token, if
    /// available.</description></item> <item><description><c>"token_use"</c>: The intended use of the token (e.g.,
    /// access or ID token).</description></item> </list> If the token is invalid or cannot be read, the dictionary will
    /// contain only <c>"active": false</c>.</returns>
    public static ApiResult<Dictionary<string, object>> IntrospectToken(string token, string clientId, IPAddress? ip, string? ua, AppConfig config)
    {
        var handler = new JwtSecurityTokenHandler();

        if (!handler.CanReadToken(token))
            return ApiResult<Dictionary<string, object>>.Ok(new Dictionary<string, object> { ["active"] = false });

        try
        {
            var principal = handler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = config.OidcIssuer,
                ValidateAudience = false,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = TokenKeyCache.GetPublicKey(isAdmin: false),
                NameClaimType = JwtRegisteredClaimNames.Sub,
                RoleClaimType = ClaimTypes.Role
            }, out var validatedToken);

            var jwt = (JwtSecurityToken)validatedToken;

            // check blacklist for revoked tokens
            if (IsRevokedJti(jwt.Id))
                return ApiResult<Dictionary<string, object>>.Ok(new() { ["active"] = false });

            // check if token's session is deleted/revoked
            var madUse = jwt.Claims.FirstOrDefault(c => c.Type == "mad")?.Value ?? "auth";

            if (madUse == "auth")
            {
                var isRevoked = UserStore.IsTokenRevoked(token);

                if (isRevoked)
                    return ApiResult<Dictionary<string, object>>.Ok(new() { ["active"] = false });
            }
            else
            {
                Log.Debug("Introspection for non-auth token (use = {Use})", madUse);

                if (config.EnableAuditLogging)
                    Utils.Audit.Logg(
                        action: "token.introspect.non_auth",
                        target: $"client={clientId} mad={madUse}"
                    );
            }

            var dict = new Dictionary<string, object>
            {
                ["active"] = true,
                ["iss"] = jwt.Issuer,
                ["jti"] = jwt.Id,
                ["sub"] = jwt.Subject,
                ["exp"] = jwt.Payload.Expiration ?? 0L,
                ["iat"] = new DateTimeOffset(jwt.Payload.IssuedAt).ToUnixTimeSeconds(),
                ["nbf"] = jwt.Payload.NotBefore ?? 0L,
                ["aud"] = jwt.Audiences.FirstOrDefault() ?? "unknown",
                ["scope"] = jwt.Claims.Where(c => c.Type == "scope").Select(c => c.Value).ToArray(),
                ["client_id"] = jwt.Claims.FirstOrDefault(c => c.Type == "client_id")?.Value ?? "unknown",
                ["username"] = jwt.Claims.FirstOrDefault(c => c.Type == "username")?.Value ?? "unknown",
                ["token_use"] = jwt.Claims.FirstOrDefault(c => c.Type == "token_use")?.Value ?? "access",
                ["mad"] = jwt.Claims.FirstOrDefault(c => c.Type == "mad")?.Value ?? "auth"
            };

            if (config.EnableAuditLogging)
                Utils.Audit.Logg(
                    action: "token.introspect.success",
                    target: $"client={clientId}"
                );

            return ApiResult<Dictionary<string, object>>.Ok(dict);
        }
        catch (SecurityTokenException ex)
        {
            Log.Warning("Token introspection failed: {Message}", ex.Message);
            return ApiResult<Dictionary<string, object>>.Ok(new Dictionary<string, object> { ["active"] = false });
        }
    }

    /// <summary>
    /// Inspects a JWT token as an administrator and retrieves its claims and metadata.
    /// </summary>
    /// <remarks>This method allows administrators to inspect tokens, including expired ones, without
    /// validating their lifetime. The method logs the introspection action for auditing purposes. The caller must
    /// ensure that the provided token is in a valid JWT format; otherwise, an error result is returned.</remarks>
    /// <param name="config">The application configuration containing the OpenID Connect issuer information.</param>
    /// <param name="token">The JWT token to be introspected. Must be a valid JWT format.</param>
    /// <param name="adminUserId">The ID of the administrator performing the introspection. Can be <see langword="null"/> if not applicable.</param>
    /// <param name="ip">The IP address of the administrator performing the introspection. Can be <see langword="null"/> if not
    /// applicable.</param>
    /// <param name="ua">The user agent of the administrator performing the introspection. Can be <see langword="null"/> if not
    /// applicable.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a dictionary of claims and metadata extracted from the token. The
    /// dictionary includes the token's claims, a <c>"valid"</c> key indicating whether the token is valid, and an
    /// <c>"expired"</c> key indicating whether the token has expired. If the token is invalid, the result contains an
    /// error message and a 400 status code.</returns>
    public static ApiResult<Dictionary<string, object>> IntrospectTokenAsAdmin(
        string token,
        string? adminUserId,
        string? ip,
        string? ua,
        AppConfig config)
    {
        var handler = new JwtSecurityTokenHandler();

        // Step 1: Decode without validating
        JwtSecurityToken decoded;
        try
        {
            decoded = handler.ReadJwtToken(token);
        }
        catch
        {
            return ApiResult<Dictionary<string, object>>.Fail("Invalid token format", 400);
        }

        // Step 2: Check the 'kid' to determine key type
        var kid = decoded.Header.Kid;
        var adminKid = TokenKeyCache.GetKeyId(isAdmin: true);

        if (kid == adminKid)
        {
            if (config.EnableAuditLogging)
                Utils.Audit.Logg(
                    action: "admin.admin.token.introspect",
                    target: "attempted introspection of admin token"
                );

            return ApiResult<Dictionary<string, object>>.Fail("Admin token introspection is not allowed", 403);
        }

        // Step 3: Proceed with normal (auth) token validation
        try
        {
            var principal = handler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = config.OidcIssuer,
                ValidateAudience = false,
                ValidateLifetime = false, // Admins may introspect expired tokens
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = TokenKeyCache.GetPublicKey(isAdmin: false),
                NameClaimType = JwtRegisteredClaimNames.Sub,
                RoleClaimType = ClaimTypes.Role
            }, out var validated);

            var jwt = (JwtSecurityToken)validated;

            var claims = jwt.Claims.ToDictionary(c => c.Type, c => (object)c.Value);
            claims["valid"] = true;
            claims["expired"] = jwt.ValidTo < DateTime.UtcNow;
            claims["iat"] = new DateTimeOffset(jwt.IssuedAt).ToUnixTimeSeconds();
            claims["nbf"] = new DateTimeOffset(jwt.ValidFrom).ToUnixTimeSeconds();
            claims["exp"] = new DateTimeOffset(jwt.ValidTo).ToUnixTimeSeconds();

            if (config.EnableAuditLogging)
                Utils.Audit.Logg(
                    action: "admin.auth.token.introspect",
                    target: jwt.Subject
                );

            return ApiResult<Dictionary<string, object>>.Ok(claims);
        }
        catch (SecurityTokenException ex)
        {
            return ApiResult<Dictionary<string, object>>.Fail($"Invalid token: {ex.Message}", 400);
        }
    }

    /// <summary>
    /// Revokes a specified JWT token by marking it as invalid in the system.
    /// </summary>
    /// <remarks>This method attempts to revoke the token by first checking for an active session associated
    /// with the token. If a session is found, it marks the session as revoked. If no session is found, the method adds
    /// the token's unique identifier (JTI) to a denylist with its expiration time.</remarks>
    /// <param name="token">The JWT token to be revoked. Must be a valid, readable token.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/> that indicates the result of the
    /// revocation. If successful, the response includes a message specifying the revocation method used. If the token
    /// is invalid or unreadable, the response contains an error message.</returns>
    public static ApiResult<MessageResponse> RevokeToken(string token)
    {
        JwtSecurityToken jwt;
        try
        {
            var handler = new JwtSecurityTokenHandler();
            jwt = handler.ReadJwtToken(token);

            var jti = jwt.Id;
            var exp = jwt.ValidTo;

            if (string.IsNullOrWhiteSpace(jti))
                return ApiResult<MessageResponse>.Fail("Token missing 'jti' claim.");

            // Try session-based revocation first
            var revoked = UserStore.RevokeToken(token);

            if (revoked > 0)
                return ApiResult<MessageResponse>.Ok(new(true, "Token revoked via session table"));

            // Otherwise, insert jti into denylist
            UserStore.AddTokenToBlacklist(jti, exp);

            return ApiResult<MessageResponse>.Ok(new(true, "Token revoked via denylist"));
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to revoke token: {Message}", ex.Message);
            return ApiResult<MessageResponse>.Fail("Internal Server Error", 500);
        }
    }

    /// <summary>
    /// Determines whether the specified JWT ID (JTI) is present in the denylist and has not yet expired.
    /// </summary>
    /// <remarks>This method queries the database to verify if the provided JTI is revoked. It checks both the
    /// presence of the JTI in the denylist and whether its expiration time is still valid. Use this method to enforce
    /// token revocation policies.</remarks>
    /// <param name="jti">The unique identifier of the JWT to check. This value cannot be null or empty.</param>
    /// <returns><see langword="true"/> if the specified JTI is found in the denylist and its expiration time has not passed;
    /// otherwise, <see langword="false"/>.</returns>
    private static bool IsRevokedJti(string jti)
    {
        try
        {
            return UserStore.IsTokenRevokedJti(jti);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Error checking if JTI {Jti} is revoked", jti);
            return true; // If there's an error, assume it's revoked
        }
    }

    /// <summary>
    /// Validates a Time-based One-Time Password (TOTP) code for a specified user.
    /// </summary>
    /// <remarks>This method retrieves the user's TOTP secret from the database and verifies the provided code
    /// against it. The user must have TOTP enabled and be active for the validation to succeed.</remarks>
    /// <param name="userId">The unique identifier of the user whose TOTP code is being validated. Cannot be null, empty, or whitespace.</param>
    /// <param name="code">The TOTP code to validate. Cannot be null, empty, or whitespace.</param>
    /// <returns><see langword="true"/> if the provided TOTP code is valid for the specified user; otherwise, <see
    /// langword="false"/>.</returns>
    public static bool ValidateTotpCode(string userId, string clientId, string code)
    {
        if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(code))
            return false;

        try
        {
            var secret = UserStore.GetTotpSecretByUserId(userId, clientId);

            if (string.IsNullOrWhiteSpace(secret))
                return false;

            var bytes = Base32Encoding.ToBytes(secret);
            var totp = new Totp(bytes); // SHA1, 30s, 6 digits
            return totp.VerifyTotp(code, out _, new VerificationWindow(1, 1));
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to validate TOTP code for user {UserId}", userId);
            return false;
        }
    }
}
