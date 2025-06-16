using System.Net;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

using Serilog;

using microauthd.Common;
using microauthd.Config;
using microauthd.Data;
using microauthd.Routes.Admin;
using microauthd.Routes.Auth;
using microauthd.Tokens;
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
                                Log.Warning("AUTH token rejected: {Error}", context.Exception?.Message);
                                return Task.CompletedTask;
                            },
                            OnTokenValidated = context =>
                            {
                                var claims = context.Principal?.Claims?.ToList() ?? new List<Claim>();
                                context.Principal = new ClaimsPrincipal(
                                    new ClaimsIdentity(claims, "Bearer", JwtRegisteredClaimNames.Sub, ClaimTypes.Role)
                                );

                                return Task.CompletedTask;
                            }
                        };
                    });
                
                if (config.EnableAuthSwagger)
                    SwaggerSetup.ConfigureServices(builder, "microauthd auth API");
            },
            app =>
            {
                app.UseAuthentication();
                app.UseAuthorization();

                if (config.EnableAuthSwagger)
                    SwaggerSetup.ConfigureApp(app);

                app.MapAuthRoutes(config);
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
                                var claims = context.Principal?.Claims?.ToList() ?? new List<Claim>();
                                context.Principal = new ClaimsPrincipal(
                                    new ClaimsIdentity(claims, "Bearer", JwtRegisteredClaimNames.Sub, ClaimTypes.Role)
                                );

                                return Task.CompletedTask;
                            }
                        };
                    });
                
                if (config.EnableAdminSwagger)
                    SwaggerSetup.ConfigureServices(builder, "microauthd admin API");
            },
            app =>
            {
                app.UseAuthentication();
                app.UseAuthorization();

                if (config.EnableAdminSwagger)
                    SwaggerSetup.ConfigureApp(app);

                app.MapAdminRoutes();
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
            builder.Services.ConfigureHttpJsonOptions(opts =>
            {
                opts.SerializerOptions.TypeInfoResolverChain.Insert(0, MicroauthJsonContext.Default);
            });

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
