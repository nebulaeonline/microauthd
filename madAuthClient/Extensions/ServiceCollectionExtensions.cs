using madAuthClient.Auth;
using madAuthClient.Options;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System.Net.Http;
namespace madAuthClient.Extensions;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddMadAuthClient(this IServiceCollection services, Action<MadAuthOptions> configure)
    {
        services.Configure(configure);

        services.AddHttpClient<MadAuthClient>((provider, client) =>
        {
            var options = provider.GetRequiredService<IOptions<MadAuthOptions>>().Value;
            client.BaseAddress = new Uri(options.AuthServerUrl);
        });

        return services;
    }
}