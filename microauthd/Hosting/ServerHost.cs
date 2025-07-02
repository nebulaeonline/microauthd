using microauthd.Common;
using microauthd.Config;
using microauthd.Data;
using microauthd.Logging;
using microauthd.Routes.Admin;
using microauthd.Routes.Auth;
using microauthd.Services;
using microauthd.Tokens;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Serilog;
using System.Net;
using System.Security.Claims;

namespace microauthd.Hosting;

public static class ServerHost
{
    // Runs both auth and admin servers concurrently
    public static async Task RunAsync(AppConfig config, string[] args)
    {
        // Intialize auth server configuration
        var authTask = RunServerAsync(
            config.AuthIp,
            config.AuthPort,
            "auth",
            builder =>
            {
                builder.Services.ConfigureHttpJsonOptions((Action<Microsoft.AspNetCore.Http.Json.JsonOptions>)(opts =>
                {
                    opts.SerializerOptions.TypeInfoResolverChain.Insert(0, (System.Text.Json.Serialization.Metadata.IJsonTypeInfoResolver)MicroauthdJsonContext.Default);
                }));
                builder.Services.AddAuthorization();
                builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                    .AddJwtBearer(options =>
                    {
                        var key = TokenKeyCache.GetPublicKey(isAdmin: false);

                        options.Configuration = null;
                        options.ConfigurationManager = null;

                        options.TokenValidationParameters = new TokenValidationParameters
                        {
                            ValidateIssuer = true,
                            ValidIssuer = config.OidcIssuer,
                            ValidateAudience = true,
                            ValidateLifetime = true,
                            ValidateIssuerSigningKey = true,
                            IssuerSigningKey = key,
                            ValidAlgorithms = new[] {
                                key switch
                                {
                                    RsaSecurityKey => SecurityAlgorithms.RsaSha256,
                                    ECDsaSecurityKey => SecurityAlgorithms.EcdsaSha256,
                                    _ => throw new InvalidOperationException("Unsupported key type")
                                }
                            },
                            NameClaimType = JwtRegisteredClaimNames.Sub,
                            RoleClaimType = ClaimTypes.Role,
                            AudienceValidator = (audiences, securityToken, validationParams) =>
                            {
                                if (securityToken is not JsonWebToken jwt)
                                {
                                    Log.Warning("Audience validation failed: token is of type {Type}", securityToken?.GetType().Name ?? "null");
                                    return false;
                                }

                                var clientId = jwt.Claims.FirstOrDefault(c => c.Type == "client_id")?.Value;
                                if (string.IsNullOrWhiteSpace(clientId))
                                {
                                    Log.Warning("Audience validation failed: missing client_id claim");
                                    return false;
                                }

                                var expectedAudience = AuthService.GetExpectedAudienceForClient(clientId);
                                if (string.IsNullOrWhiteSpace(expectedAudience))
                                {
                                    Log.Warning("Audience validation failed: unknown or inactive client_id: {ClientId}", clientId);
                                    return false;
                                }

                                if (!audiences?.Contains(expectedAudience) ?? true)
                                {
                                    Log.Warning("Audience mismatch for client_id={ClientId}: expected {Expected}, got {Got}",
                                        clientId, expectedAudience, string.Join(", ", audiences ?? Enumerable.Empty<string>()));
                                    return false;
                                }

                                return true;
                            }
                        };

                        options.Events = new JwtBearerEvents
                        {
                            OnAuthenticationFailed = context =>
                            {
                                Log.Warning("AUTH token rejected: {Error}", context.Exception?.Message);
                                return Task.CompletedTask;
                            },
                            OnTokenValidated = context =>
                            {
                                var config = context.HttpContext.RequestServices.GetRequiredService<AppConfig>();

                                var claims = context.Principal?.Claims?.ToList() ?? new List<Claim>();
                                var rawUserId = claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Sub)?.Value;
                                var madUse = claims.FirstOrDefault(c => c.Type == "mad")?.Value ?? "";
                                Guid parsed;
                                var userId = madUse == "auth" && Guid.TryParse(rawUserId, out parsed) ? rawUserId : null;
                                var jti = claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Jti)?.Value;
                                var tokenUse = claims.FirstOrDefault(c => c.Type == "token_use")?.Value;

                                // Heuristic to reject ID tokens used as access tokens
                                if (claims.Any(c => c.Type == "nonce"))
                                {
                                    Log.Warning("Rejected token with 'nonce' claim — likely an ID token misused as an access token.");
                                    context.Fail("Invalid token");
                                    return Task.CompletedTask;
                                }

                                if (tokenUse == "id")
                                {
                                    Log.Warning("Rejected microauthd ID token used for API access.");
                                    context.Fail("Invalid token");
                                    return Task.CompletedTask;
                                }

                                // Check session revocation if enabled
                                if (config.EnableTokenRevocation && madUse == "auth")
                                {
                                    if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(jti))
                                    {
                                        context.Fail("Invalid token");
                                        return Task.CompletedTask;
                                    }

                                    if (!SessionAccess.IsSessionActive(userId, jti))
                                    {
                                        Log.Warning("Replay detected: revoked token jti={Jti} user={UserId}", jti, userId);

                                        if (config.EnableAuditLogging)
                                            Utils.Audit.Logg(
                                                action: "auth.token.replay_detected",
                                                target: $"jti={jti}"
                                            );

                                        context.Fail("Invalid token");
                                        return Task.CompletedTask;
                                    }
                                }

                                // Replace principal to bind correct claim types
                                context.Principal = new ClaimsPrincipal(
                                    new ClaimsIdentity(claims, "Bearer", JwtRegisteredClaimNames.Sub, ClaimTypes.Role)
                                );

                                return Task.CompletedTask;
                            }
                        };
                    });
                
                if (config.EnableAuthSwagger)
                    SwaggerSetup.ConfigureServices(builder, "microauthd auth API");

                // Register http context accessor
                builder.Services.AddHttpContextAccessor();

                // Register the audit logging service
                builder.Services.AddSingleton<AuditDos>();

                // Set up our scheduled task service
                builder.Services.AddHostedService<ScheduledTaskService>();

                // Set up our anti-forgery token service
                builder.Services.AddAntiforgery(options =>
                {
                    options.HeaderName = "X-CSRF-TOKEN";
                });
            },
            app =>
            {
                // set up forwarded headers if behind a reverse proxy
                if (config.TrustedProxies.Any())
                {
                    var forwarded = new ForwardedHeadersOptions
                    {
                        ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto,
                        ForwardLimit = null,
                        RequireHeaderSymmetry = false
                    };

                    foreach (var ip in config.TrustedProxies)
                    {
                        if (IPAddress.TryParse(ip, out var parsed))
                            forwarded.KnownProxies.Add(parsed);
                        else
                            Log.Warning("Invalid trusted proxy: {Ip}", ip);
                    }

                    app.UseForwardedHeaders(forwarded);
                }
                else
                {
                    Log.Information("No trusted proxies configured — forwarded headers will be ignored.");
                }

                // Use rate limiting middleware for auth routes
                app.UseMiddleware<RateLimitMiddleware>("auth");

                app.UseAuthentication();
                app.UseAuthorization();

                if (config.EnableAuthSwagger)
                    SwaggerSetup.ConfigureApp(app);

                app.MapAuthRoutes(config);

                // set up static file serving, if enabled
                if (config.ServePublicAuthFiles)
                {
                    var publicPath = Path.Combine(Directory.GetCurrentDirectory(), "public");
                    var fileProvider = new PhysicalFileProvider(publicPath);

                    app.UseDefaultFiles(new DefaultFilesOptions
                    {
                        FileProvider = fileProvider,
                        RequestPath = ""
                    });

                    app.UseStaticFiles(new StaticFileOptions
                    {
                        FileProvider = fileProvider,
                        RequestPath = ""
                    });

                    app.UseAntiforgery();
                }
            },
            config
        );

        // Intialize admin server configuration
        var adminTask = RunServerAsync(
            config.AdminIp,
            config.AdminPort,
            "admin",
            builder =>
            {
                builder.Services.ConfigureHttpJsonOptions((Action<Microsoft.AspNetCore.Http.Json.JsonOptions>)(opts =>
                {
                    opts.SerializerOptions.TypeInfoResolverChain.Insert(0, (System.Text.Json.Serialization.Metadata.IJsonTypeInfoResolver)MicroauthdJsonContext.Default);
                }));
                
                builder.Services.AddAuthorization();
                builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                    .AddJwtBearer(options =>
                    {
                        var key = TokenKeyCache.GetPublicKey(isAdmin: true);

                        options.Configuration = null;
                        options.ConfigurationManager = null;

                        options.TokenValidationParameters = new TokenValidationParameters
                        {
                            ValidateIssuer = true,
                            ValidIssuer = config.OidcIssuer,
                            ValidateAudience = false,
                            ValidateLifetime = true,
                            ValidateIssuerSigningKey = true,
                            IssuerSigningKey = key,
                            ValidAlgorithms = new[] {
                                key switch
                                {
                                    RsaSecurityKey => SecurityAlgorithms.RsaSha256,
                                    ECDsaSecurityKey => SecurityAlgorithms.EcdsaSha256,
                                    _ => throw new InvalidOperationException("Unsupported key type")
                                }
                            },
                            NameClaimType = JwtRegisteredClaimNames.Sub,
                            RoleClaimType = ClaimTypes.Role
                        };

                        options.Events = new JwtBearerEvents
                        {
                            OnAuthenticationFailed = context =>
                            {
                                Log.Warning("ADMIN token rejected: {Error}", context.Exception?.Message);
                                return Task.CompletedTask;
                            },
                            OnTokenValidated = context =>
                            {
                                var config = context.HttpContext.RequestServices.GetRequiredService<AppConfig>();

                                var claims = context.Principal?.Claims?.ToList() ?? new List<Claim>();
                                var userId = claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Sub)?.Value;
                                var jti = claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Jti)?.Value;

                                // Check session revocation if enabled
                                if (config.EnableTokenRevocation)
                                {
                                    if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(jti))
                                    {
                                        context.Fail("Invalid token");
                                        return Task.CompletedTask;
                                    }

                                    if (!SessionAccess.IsSessionActive(userId, jti))
                                    {
                                        Log.Warning("Replay detected: revoked token jti={Jti} user={UserId}", jti, userId);

                                        if (config.EnableAuditLogging)
                                            Utils.Audit.Logg(
                                                action: "admin.token.replay_detected",
                                                target: $"jti={jti}"
                                            );

                                        context.Fail("Invalid token");
                                        return Task.CompletedTask;
                                    }
                                }

                                // Replace principal to bind correct claim types
                                context.Principal = new ClaimsPrincipal(
                                    new ClaimsIdentity(claims, "Bearer", JwtRegisteredClaimNames.Sub, ClaimTypes.Role)
                                );

                                return Task.CompletedTask;
                            }
                        };
                    })
                    .AddCookie("Cookies", options =>
                    {
                        options.LoginPath = "/Login";
                        options.AccessDeniedPath = "/AccessDenied";

                        // Allow cookie over HTTP for dev, but secure in prod
                        options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
                        options.Cookie.HttpOnly = true;
                        options.Cookie.SameSite = SameSiteMode.Lax;
                        options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
                        options.SlidingExpiration = true;
                        options.Cookie.Name = "microauthd.session";
                    });


                if (config.EnableAdminSwagger)
                    SwaggerSetup.ConfigureServices(builder, "microauthd admin API");

                // Register razor pages for admin UI
                builder.Services.AddAntiforgery(options => {
                    options.SuppressXFrameOptionsHeader = true;
                    options.HeaderName = "X-CSRF-TOKEN"; // Use header for CSRF token
                });

                // Enable Razor Pages with auto antiforgery token validation
                builder.Services.AddRazorPages(options =>
                {
                    options.Conventions.ConfigureFilter(new AutoValidateAntiforgeryTokenAttribute());
                });

                // Register http context accessor
                builder.Services.AddHttpContextAccessor();

                // Register the audit logging service
                builder.Services.AddSingleton<AuditDos>();
            },
            app =>
            {
                // Use forwarded headers if behind a reverse proxy
                if (config.TrustedProxies.Any())
                {
                    var forwarded = new ForwardedHeadersOptions
                    {
                        ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto,
                        ForwardLimit = null,
                        RequireHeaderSymmetry = false
                    };

                    foreach (var ip in config.TrustedProxies)
                    {
                        if (IPAddress.TryParse(ip, out var parsed))
                            forwarded.KnownProxies.Add(parsed);
                        else
                            Log.Warning("Invalid trusted proxy: {Ip}", ip);
                    }

                    app.UseForwardedHeaders(forwarded);
                }
                else
                {
                    Log.Information("No trusted proxies configured — forwarded headers will be ignored.");
                }

                // Use rate limiting middleware for admin routes too
                app.UseMiddleware<RateLimitMiddleware>("admin");

                // Standard middleware setup
                app.UseStaticFiles();   // wwwroot files
                app.UseRouting();

                app.UseAuthentication();
                app.UseAuthorization();

                // Enable Swagger UI if configured
                if (config.EnableAdminSwagger)
                    SwaggerSetup.ConfigureApp(app);

                // Use cookie authorization (once authenticated)
                app.MapRazorPages()
                   .RequireAuthorization(new AuthorizeAttribute
                   {
                       AuthenticationSchemes = "Cookies"
                   });

                // APIs use JWT Bearer authentication
                app.MapAdminRoutes(config)
                   .RequireAuthorization(new AuthorizeAttribute
                   {
                       AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme
                   });
            },
            config
        );

        await Task.WhenAll(authTask, adminTask);
    }

    // Runs a single server with the specified configuration
    private static async Task RunServerAsync(
        string ip,
        int port,
        string tag,
        Action<WebApplicationBuilder> configureBuilder,
        Action<WebApplication> configureApp,
        AppConfig config
    )
    {
        try
        {
            // Create the web application builder with the specified options
            var builder = WebApplication.CreateBuilder(new WebApplicationOptions
            {
                ContentRootPath = Directory.GetCurrentDirectory(),
                EnvironmentName = Environments.Production
            });

            // Prevent hosting startup to avoid unnecessary middleware
            builder.WebHost.UseSetting(WebHostDefaults.PreventHostingStartupKey, "true");

            // Register our json serializer context
            builder.Services.ConfigureHttpJsonOptions((Action<Microsoft.AspNetCore.Http.Json.JsonOptions>)(opts =>
            {
                opts.SerializerOptions.TypeInfoResolverChain.Insert(0, (System.Text.Json.Serialization.Metadata.IJsonTypeInfoResolver)MicroauthdJsonContext.Default);
            }));

            // Enable verbose model binding error logging
            builder.Services.Configure<ApiBehaviorOptions>(options =>
            {
                options.SuppressModelStateInvalidFilter = false;
            });

            // Inject AppConfig
            builder.Services.AddSingleton<AppConfig>(config);

            // Configure the Kestrel server
            builder.WebHost.ConfigureKestrel(options =>
            {
                var endpoint = IPAddress.Parse(ip);

                options.Listen(endpoint, port, listen =>
                {
                    if (tag == "auth" && !string.IsNullOrEmpty(config.AuthSSLCertFile))
                    {
                        if (string.IsNullOrEmpty(config.AuthSSLCertPass))
                            listen.UseHttps(config.AuthSSLCertFile);
                        else
                            listen.UseHttps(config.AuthSSLCertFile, config.AuthSSLCertPass);
                    }
                    else if (tag == "admin" && !string.IsNullOrEmpty(config.AdminSSLCertFile))
                    {
                        if (string.IsNullOrEmpty(config.AdminSSLCertPass))
                            listen.UseHttps(config.AdminSSLCertFile);
                        else
                            listen.UseHttps(config.AdminSSLCertFile, config.AdminSSLCertPass);
                    }                    
                });
            });

            configureBuilder(builder);

            var app = builder.Build();
            Utils.Init(app.Services);

            configureApp(app);

            Log.Information("Starting {Tag} server on {Ip}:{Port}", tag, ip, port);
            if ((tag == "auth" && config.EnableAuthSwagger) || (tag == "admin" && config.EnableAdminSwagger))
                Log.Information("{0} Swagger UI available at http://{1}:{2}/swagger", tag, ip, port);
            
            await app.RunAsync();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[FATAL] Failed to start {tag} server: {ex.Message}");
            Log.Fatal(ex, "Failed to start {Tag} server", tag);
        }
    }
}
