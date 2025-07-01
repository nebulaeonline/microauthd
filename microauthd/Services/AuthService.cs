using madTypes.Api.Common;
using madTypes.Api.Requests;
using madTypes.Api.Responses;
using madTypes.Common;
using microauthd.Common;
using microauthd.Config;
using microauthd.Data;
using microauthd.Tokens;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
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
    /// Handles an OAuth 2.0 authorization request and generates an authorization code.
    /// </summary>
    /// <remarks>This method processes the query parameters of an incoming HTTP request to validate and handle
    /// an authorization request in accordance with the OAuth 2.0 specification. It validates required parameters,
    /// checks for supported values, and generates an authorization code if the request is valid. The generated code is
    /// stored for later use in the authorization flow.</remarks>
    /// <param name="req">The incoming HTTP request containing the authorization query parameters. The request must include the following
    /// parameters: <list type="bullet"> <item><term>response_type</term>: Must be "code".</item>
    /// <item><term>client_id</term>: The client identifier.</item> <item><term>redirect_uri</term>: The URI to redirect
    /// the user after authorization.</item> <item><term>scope</term>: The requested scope of access (optional).</item>
    /// <item><term>state</term>: A value used to maintain state between the request and callback (optional).</item>
    /// <item><term>code_challenge</term>: The PKCE code challenge.</item> <item><term>code_challenge_method</term>: The
    /// method used to transform the code challenge. Must be "S256" or "plain".</item> </list></param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a dictionary with the following keys: <list type="bullet">
    /// <item><term>code</term>: The generated authorization code.</item> <item><term>state</term>: The state value
    /// provided in the request, if any.</item> </list> If the request is invalid, the result contains an error message
    /// and a corresponding HTTP status code.</returns>
    public static IResult HandleAuthorizationRequest(HttpRequest req, AppConfig config)
    {
        var query = req.Query;

        var responseType = query["response_type"].ToString();
        var clientId = query["client_id"].ToString(); // Client identifier (not row id)
        var redirectUri = query["redirect_uri"].ToString();
        var scope = query["scope"].ToString();
        var state = query["state"].ToString();
        var codeChallenge = query["code_challenge"].ToString();
        var codeChallengeMethod = query["code_challenge_method"].ToString();
        var nonce = query["nonce"].ToString();

        if (string.IsNullOrWhiteSpace(responseType) || responseType != "code")
            return Results.BadRequest("Invalid credentials");

        if (string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(redirectUri))
            return Results.BadRequest("Invalid credentials");

        if (string.IsNullOrWhiteSpace(codeChallenge))
            return Results.BadRequest("Invalid credentials");

        if (codeChallengeMethod != "S256" && codeChallengeMethod != "plain")
            return Results.BadRequest("Invalid credentials");

        if (!AuthStore.IsRedirectUriValid(clientId, redirectUri))
        {
            Log.Warning("Authorization request rejected: invalid redirect_uri {RedirectUri} for client_id {ClientId}", redirectUri, clientId);
            return Results.BadRequest("Invalid credentials");
        }

        // If scope includes 'openid', and nonce is missing — reject the request
        if (scope.Split(' ', StringSplitOptions.RemoveEmptyEntries).Contains("openid") &&
            string.IsNullOrWhiteSpace(nonce))
        {
            Log.Warning("Authorization request rejected: openid scope requires nonce");
            return Results.BadRequest("Invalid credentials");
        }

        // Generate and store auth code
        var code = Utils.GenerateBase64EncodedRandomBytes(32);

        var pkceCode = new PkceCode
        {
            Code = code,
            ClientIdentifier = clientId,
            UserId = "",
            RedirectUri = redirectUri,
            CodeChallenge = codeChallenge,
            CodeChallengeMethod = codeChallengeMethod,
            ExpiresAt = DateTime.UtcNow.AddSeconds(config.PkceCodeLifetime),
            IsUsed = false,
            Nonce = nonce
        };

        AuthStore.StorePkceCode(pkceCode);

        var redirectUrl = $"{redirectUri}?code={WebUtility.UrlEncode(code)}&state={WebUtility.UrlEncode(state)}";
        return Results.Redirect(redirectUrl);
    }


    /// <summary>
    /// Exchanges a PKCE authorization code for a token response.
    /// </summary>
    /// <remarks>This method validates the provided PKCE authorization code and associated parameters,
    /// ensuring that the code has not expired or been used, and that the client ID, redirect URI, and code verifier
    /// match the expected values. If validation succeeds, the method marks the authorization code as used and attempts
    /// to issue a token response. Currently, the PKCE flow is not fully implemented to associate the authorization code
    /// with a user session.</remarks>
    /// <param name="form">A collection of form data containing the required parameters for the PKCE exchange. The following keys are
    /// expected: <list type="bullet"> <item><term>code</term><description>The PKCE authorization
    /// code.</description></item> <item><term>client_id</term><description>The client identifier associated with the
    /// authorization code.</description></item> <item><term>code_verifier</term><description>The code verifier used to
    /// validate the code challenge.</description></item> <item><term>redirect_uri</term><description>The redirect URI
    /// used during the authorization request.</description></item> </list></param>
    /// <returns>An <see cref="ApiResult{TokenResponse}"/> containing the token response if the exchange is successful. If
    /// validation fails, the result contains an error message and an appropriate HTTP status code.</returns>
    public static ApiResult<TokenResponse> ExchangePkceCode(IFormCollection form, AppConfig config)
    {
        if (!config.EnablePkce)
            return ApiResult<TokenResponse>.Forbidden("Invalid credentials");

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
            return ApiResult<TokenResponse>.Forbidden("Invalid credentials");
        }

        var pkce = AuthStore.GetPkceCode(code);
        if (pkce is null)
        {
            Log.Warning("PKCE exchange failed: code not found. client_id={ClientId}, code={Code}", clientId, code);
            return ApiResult<TokenResponse>.Forbidden("Invalid credentials");
        }

        if (pkce.IsUsed)
        {
            Log.Warning("PKCE exchange failed: code already used. client_id={ClientId}, code={Code}", clientId, code);
            return ApiResult<TokenResponse>.Forbidden("Invalid credentials");
        }

        if (pkce.ExpiresAt < DateTime.UtcNow)
        {
            Log.Warning("PKCE exchange failed: code expired. client_id={ClientId}, code={Code}, expired_at={ExpiredAt}", clientId, code, pkce.ExpiresAt);
            return ApiResult<TokenResponse>.Forbidden("Invalid credentials");
        }

        if (!string.Equals(pkce.ClientIdentifier, clientId, StringComparison.Ordinal) ||
            !string.Equals(pkce.RedirectUri, redirectUri, StringComparison.Ordinal))
        {
            Log.Warning("PKCE exchange failed: client_id or redirect_uri mismatch. client_id={ClientId}, expected_client_id={Expected}, redirect_uri={RedirectUri}, expected_redirect_uri={ExpectedUri}",
                clientId, pkce.ClientIdentifier, redirectUri, pkce.RedirectUri);
            return ApiResult<TokenResponse>.Forbidden("Invalid credentials");
        }

        var challengeValid = pkce.CodeChallengeMethod.ToLowerInvariant() switch
        {
            "plain" => pkce.CodeChallenge == codeVerifier,
            "s256" => pkce.CodeChallenge == Utils.ComputeS256Challenge(codeVerifier),
            _ => false
        };

        if (!challengeValid)
        {
            Log.Warning("PKCE exchange failed: code_verifier did not match challenge. client_id={ClientId}, method={Method}", clientId, pkce.CodeChallengeMethod);
            return ApiResult<TokenResponse>.Forbidden("Invalid credentials");
        }

        AuthStore.MarkPkceCodeAsUsed(code);

        if (string.IsNullOrWhiteSpace(pkce.UserId))
        {
            Log.Warning("PKCE exchange failed: no user associated with code. client_id={ClientId}, code={Code}", clientId, code);
            return ApiResult<TokenResponse>.Forbidden("Invalid credentials");
        }

        // retrieve the user object for email claim
        var user = UserStore.GetUserById(pkce.UserId);
        if (user == null)
            return ApiResult<TokenResponse>.Forbidden("Invalid credentials");

        var claims = AuthStore.GetUserClaims(pkce.UserId);
        claims.Insert(0, new Claim(JwtRegisteredClaimNames.Sub, pkce.UserId));
        claims.Add(new Claim(JwtRegisteredClaimNames.Email, user.Email ?? ""));
        claims.Add(new Claim("client_id", pkce.ClientIdentifier));
        
        var scopeValues = claims
            .Where(c => c.Type == "scope")
            .Select(c => c.Value)
            .Distinct()
            .ToArray();

        if (scopeValues.Any())
            claims.Add(new Claim("scope", string.Join(' ', scopeValues)));

        var audience = ClientStore.GetClientAudienceByIdentifier(pkce.ClientIdentifier);

        var tokenInfo = TokenIssuer.IssueToken(config, claims, isAdmin: false, audience);

        UserService.WriteSessionToDb(tokenInfo, config, pkce.ClientIdentifier);

        string? refreshToken = null;
        if (config.EnableTokenRefresh)
        {
            refreshToken = UserService.GenerateAndStoreRefreshToken(
                config, pkce.UserId, tokenInfo.Jti, pkce.ClientIdentifier);
        }

        string? idToken = null;
        if (scopeValues.Contains("openid"))
        {
            idToken = TokenIssuer.IssueIdToken(config, claims, pkce.ClientIdentifier, pkce.Nonce);
        }

        // attach the JTI to the PKCE code for later reference
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
    /// Handles user login using a PKCE code and validates the provided credentials.
    /// </summary>
    /// <remarks>This method validates the provided PKCE code, ensuring it is not expired, used, or mismatched
    /// with the redirect URI. It also verifies the user's credentials against the application's authentication
    /// settings. If the login is successful, the user's ID is attached to the PKCE code record.</remarks>
    /// <param name="username">The username of the user attempting to log in. Cannot be null, empty, or whitespace.</param>
    /// <param name="password">The password associated with the username. Cannot be null, empty, or whitespace.</param>
    /// <param name="code">The PKCE code used for authentication. Cannot be null, empty, or whitespace.</param>
    /// <param name="redirectUri">The redirect URI associated with the PKCE code. Must match the URI stored with the code. Cannot be null, empty,
    /// or whitespace.</param>
    /// <param name="config">The application configuration containing authentication settings. Cannot be null.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="MessageResponse"/> indicating the result of the login
    /// attempt. Returns <see langword="true"/> in the response if the login is successful; otherwise, <see
    /// langword="false"/>.</returns>
    public static ApiResult<MessageResponse> HandleUserLoginWithCode(
        string username,
        string password,
        string code,
        string redirectUri,
        AppConfig config)
    {
        if (string.IsNullOrWhiteSpace(username) ||
            string.IsNullOrWhiteSpace(password) ||
            string.IsNullOrWhiteSpace(code) ||
            string.IsNullOrWhiteSpace(redirectUri))
        {
            return ApiResult<MessageResponse>.Forbidden("Invalid credentials");
        }

        var pkce = AuthStore.GetPkceCode(code);
        if (pkce is null || pkce.IsUsed || pkce.ExpiresAt < DateTime.UtcNow)
        {
            Log.Warning("Rejected login: code missing/expired/used");
            return ApiResult<MessageResponse>.Forbidden("Invalid credentials");
        }

        if (!string.Equals(pkce.RedirectUri, redirectUri, StringComparison.Ordinal))
        {
            Log.Warning("Rejected login: redirect_uri mismatch");
            return ApiResult<MessageResponse>.Forbidden("Invalid credentials");
        }

        var authResult = AuthenticateUser(username, password, config);
        if (authResult is not { Success: true } r)
        {
            Log.Warning("Failed login attempt for {Username}", username);
            return ApiResult<MessageResponse>.Forbidden("Invalid credentials");
        }

        // Save user ID to pkce code record
        AuthStore.AttachUserIdToPkceCode(code, r.UserId!);

        Log.Debug("Login successful for user {UserId} via PKCE", r.UserId);

        return ApiResult<MessageResponse>.Ok(new MessageResponse(true, "Login successful"));
    }

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
        string ua
    )
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

        var tokenInfo = TokenIssuer.IssueToken(config, claims, isAdmin: true);

        UserService.WriteSessionToDb(tokenInfo, config, req.ClientIdentifier ?? "admin");

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
            string.IsNullOrWhiteSpace(clientIdent))
            return ApiResult<TokenResponse>.Forbidden("Invalid credentials");

        // check the DB for the client identifier
        if (string.IsNullOrEmpty(clientIdent))
        {
            Log.Warning("Unknown or inactive client_identifier {ClientIdent}. IP {IP} UA {UA}", clientIdent, ip, userAgent);
            return ApiResult<TokenResponse>.Forbidden("Invalid credentials");
        }

        if (!ValidateOidcClient(clientIdent, clientSecret, config))
        {
            Log.Warning("Client authentication failed for {ClientId}. IP {IP} UA {UA}", clientIdent, ip, userAgent);
            return ApiResult<TokenResponse>.Forbidden("Invalid credentials");
        }

        try
        {
            // Get the audience for the client identifier
            var audience = ClientStore.GetClientAudienceByIdentifier(clientIdent);

            // Must have a valid audience
            if (string.IsNullOrWhiteSpace(audience))
            {
                Log.Warning("Client identifier not found or missing audience: {ClientId}", clientIdent);
                return ApiResult<TokenResponse>.Forbidden("Invalid credentials");
            }

            // Authenticate user
            var result = AuthenticateUser(username, password, config);
            if (result is not { Success: true } r)
            {
                Log.Warning("Failed login attempt for {Username}. IP {IP} UA {UA}", username, ip, userAgent);
                return ApiResult<TokenResponse>.Forbidden("Invalid credentials");
            }

            // Check if TOTP is required for this user
            var requiresTotp = UserStore.IsTotpEnabledForUserId(r.UserId!);
            if (requiresTotp)
            {
                var totpCode = form["totp_code"].ToString();
                if (string.IsNullOrWhiteSpace(totpCode) || !ValidateTotpCode(r.UserId!, totpCode))
                {
                    Log.Warning("TOTP required and failed for user {UserId}", r.UserId);
                    return ApiResult<TokenResponse>.Forbidden("Invalid credentials");
                }
            }

            // Assemble base claims
            var claims = new List<Claim>
            {
                new(JwtRegisteredClaimNames.Sub, r.UserId!),
                new(JwtRegisteredClaimNames.Email, r.Email ?? ""),
                new("client_id", clientIdent)
            };

            // Extract role + scope claims from r.Claims
            var roleClaims = r.Claims.Where(c => c.Type == "role");
            var scopeValues = r.Claims
                .Where(c => c.Type == "scope")
                .Select(c => c.Value)
                .Distinct();

            claims.AddRange(roleClaims);

            // Add email_verified if present
            var emailVerifiedClaim = r.Claims.FirstOrDefault(c => c.Type == "email_verified");
            if (emailVerifiedClaim != null)
            {
                claims.Add(emailVerifiedClaim);
            }

            if (scopeValues.Any())
                claims.Add(new Claim("scope", string.Join(' ', scopeValues)));

            // Issue JWT
            var tokenInfo = TokenIssuer.IssueToken(config, claims, isAdmin: false, audience: audience);
            UserService.WriteSessionToDb(tokenInfo, config, clientIdent);

            // Optionally generate refresh token
            string? refreshToken = null;
            if (config.EnableTokenRefresh)
            {
                refreshToken = UserService.GenerateAndStoreRefreshToken(
                    config, tokenInfo.UserId, tokenInfo.Jti, clientIdent);
            }

            // Optionally generate id token
            string? idToken = null;
            if (scopeValues.Contains("openid"))
            {
                idToken = TokenIssuer.IssueIdToken(config, claims, clientIdent);
            }

            Log.Debug("Issued token for user {UserId} under client {ClientIdent}", r.UserId, clientIdent);

            // No need to audit log every token issuance, only for admin tokens or significant events
            //Utils.Audit.Logg(
            //    action: "token_issued",
            //    target: clientIdent
            //);

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
        try
        {
            // Get the raw token and make sure it's not empty
            var raw = form["refresh_token"].ToString();
            var clientId = form["client_id"].ToString();
            var clientSecret = form["client_secret"].ToString();

            if (string.IsNullOrWhiteSpace(raw))
                return ApiResult<TokenResponse>.Fail("Missing refresh token", 400);

            if (!ValidateOidcClient(clientId, clientSecret, config))
            {
                Log.Warning("Refresh token request failed client validation: {ClientId}", clientId);
                return ApiResult<TokenResponse>.Forbidden("Invalid credentials");
            }

            // Lookup the refresh token by sha256 hash
            var sha256 = Utils.Sha256Base64(raw);
            var tokenRow = UserStore.GetRefreshTokenBySha256Hash(sha256);

            // If the refresh token is null, revoked, or expired, return forbidden
            if (tokenRow is null || tokenRow.IsRevoked || tokenRow.ExpiresAt < DateTime.UtcNow)
                return ApiResult<TokenResponse>.Forbidden("Invalid credentials");

            // Revoke the token to prevent reuse
            UserStore.RevokeRefreshToken(tokenRow.Id);

            // Build claims (initial set)
            var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, tokenRow.UserId),
            new("client_id", tokenRow.ClientIdentifier)
        };

            // Retrieve roles and scopes
            var userClaims = AuthStore.GetUserClaims(tokenRow.UserId);
            var roleClaims = userClaims.Where(c => c.Type == "role");
            var scopeClaims = userClaims.Where(c => c.Type == "scope").Select(c => c.Value).Distinct();

            claims.AddRange(roleClaims);

            // Add email_verified if present
            var emailVerifiedClaim = userClaims.FirstOrDefault(c => c.Type == "email_verified");
            if (emailVerifiedClaim != null)
            {
                claims.Add(emailVerifiedClaim);
            }

            // Add single OAuth2-style space-delimited scope claim
            if (scopeClaims.Any())
                claims.Add(new Claim("scope", string.Join(' ', scopeClaims)));

            // Get the audience for the given client identifier
            var audience = ClientStore.GetClientAudienceByIdentifier(tokenRow.ClientIdentifier);

            // Issue the new token and store it in the session table
            var tokenInfo = TokenIssuer.IssueToken(config, claims, isAdmin: false, audience: audience);
            UserService.WriteSessionToDb(tokenInfo, config, tokenRow.ClientIdentifier);

            // Generate and store a new refresh token
            var newRefreshToken = UserService.GenerateAndStoreRefreshToken(
                config,
                tokenRow.UserId,
                tokenInfo.Jti,
                tokenRow.ClientIdentifier
            );

            if (config.EnableAuditLogging)
                Utils.Audit.Logg(
                    action: "refresh_token_used",
                    target: tokenRow.ClientIdentifier
                );

            // Generate a new id token
            string? idToken = null;
            if (scopeClaims.Contains("openid"))
            {
                idToken = TokenIssuer.IssueIdToken(config, claims, tokenRow.ClientIdentifier);
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
            ResponseTypesSupported = new[] { "token" },
            SubjectTypesSupported = new[] { "public" },
            IdTokenSigningAlgValuesSupported = new[] { "RS256", "ES256" },
            ScopesSupported = new[] { "openid", "email", "profile" },
            ClaimsSupported = new[] { "sub", "email", "jti", "iat", "exp", "aud", "iss", "token_use" },
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
                new("token_use", "client")
            };

            if (scopes.Count > 0)
                claims.Add(new Claim("scope", string.Join(' ', scopes)));

            var audience = ClientStore.GetClientAudienceByIdentifier(clientId);

            var tokenInfo = TokenIssuer.IssueToken(config, claims, isAdmin: false, audience: audience);

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
            var tokenUse = jwt.Claims.FirstOrDefault(c => c.Type == "token_use")?.Value ?? "auth";

            if (tokenUse == "auth")
            {
                var isRevoked = UserStore.IsTokenRevoked(token);

                if (isRevoked)
                    return ApiResult<Dictionary<string, object>>.Ok(new() { ["active"] = false });
            }
            else
            {
                Log.Debug("Introspection for non-auth token (use = {Use})", tokenUse);

                if (config.EnableAuditLogging)
                    Utils.Audit.Logg(
                        action: "token.introspect.non_auth",
                        target: $"client={clientId} token_use={tokenUse}"
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
                ["token_use"] = jwt.Claims.FirstOrDefault(c => c.Type == "token_use")?.Value ?? "auth"
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
    public static bool ValidateTotpCode(string userId, string code)
    {
        if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(code))
            return false;

        try
        {
            var secret = UserStore.GetTotpSecretByUserId(userId);

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

    /// <summary>
    /// Verifies the provided username and password credentials and determines if additional authentication steps are
    /// required.
    /// </summary>
    /// <remarks>This method checks the validity of the provided username and password against the
    /// authentication service. If the credentials are valid, it also determines whether Time-based One-Time Password
    /// (TOTP) authentication is required for the user. The result includes the user's ID, email, and TOTP requirement
    /// status.</remarks>
    /// <param name="req">The request containing the username and password to verify.</param>
    /// <param name="config">The application configuration used for authentication.</param>
    /// <returns>An <see cref="ApiResult{T}"/> containing a <see cref="VerifyPasswordResponse"/> object if the credentials are
    /// valid. If the credentials are invalid, the result will indicate the failure reason and status code.</returns>
    public static ApiResult<VerifyPasswordResponse> VerifyPasswordOnly(VerifyPasswordRequest req, AppConfig config)
    {
        if (string.IsNullOrWhiteSpace(req.Username) || string.IsNullOrWhiteSpace(req.Password))
            return ApiResult<VerifyPasswordResponse>.Forbidden("Invalid credentials");

        var result = AuthService.AuthenticateUser(req.Username, req.Password, config);
        if (result is not { Success: true } r)
            return ApiResult<VerifyPasswordResponse>.Forbidden("Invalid credentials");

        var totpRequired = UserStore.IsTotpEnabledForUserId(r.UserId!);

        return ApiResult<VerifyPasswordResponse>.Ok(new VerifyPasswordResponse
        {
            Valid = true,
            UserId = r.UserId,
            Email = r.Email,
            TotpRequired = totpRequired
        });
    }

}
