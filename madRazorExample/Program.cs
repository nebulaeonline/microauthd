using madAuthClient.Auth;
using madAuthClient.Extensions;
using madAuthClient.Options;
using Microsoft.AspNetCore.Authentication.Cookies;

var builder = WebApplication.CreateBuilder(args);

// Razor Pages
builder.Services.AddRazorPages();

// Cookie Authentication
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
    {
        options.LoginPath = "/Login";
        options.LogoutPath = "/Logout";
        options.Cookie.Name = "mad.session";
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
        options.SlidingExpiration = true;
    });

// madAuthClient config
builder.Services.AddMadAuthClient(options =>
{
    options.AuthServerUrl = "https://localhost:9040";   // Update as needed
    options.ClientId = "demo-client";
    options.ClientSecret = "demo-secret";
    options.CookieName = "mad.session";
    options.AutoRefreshSkewSeconds = 60;
    options.EnableDebugLogging = true;
});

var app = builder.Build();

// Static files, routing, and security
app.UseStaticFiles();
app.UseRouting();

app.UseAuthentication();
app.UseMiddleware<RefreshTokenMiddleware>(); // Refresh before authz
app.UseAuthorization();

app.MapRazorPages();

app.Run();
