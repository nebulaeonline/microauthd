using Microsoft.OpenApi.Models;

namespace microauthd.Hosting;

public static class SwaggerSetup
{
    public static void ConfigureServices(WebApplicationBuilder builder, string title)
    {
        builder.Services.AddEndpointsApiExplorer();
        builder.Services.AddSwaggerGen(options =>
        {
            options.SwaggerDoc("v1", new OpenApiInfo
            {
                Title = title,
                Version = "v1"
            });
        });
    }

    public static void ConfigureApp(WebApplication app)
    {
        app.UseSwagger();
        app.UseSwaggerUI(options =>
        {
            options.SwaggerEndpoint("/swagger/v1/swagger.json", "v1");
        });
    }
}
