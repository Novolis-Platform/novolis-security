using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Novolis.Security.Authentication;

namespace Novolis.Security.HaveIBeenPwned;

/// <summary>Registers the Have I Been Pwned range client as an <see cref="IPasswordBreachChecker"/>.</summary>
public static class HaveIBeenPwnedServiceCollectionExtensions
{
    /// <summary>Registers the pinned Pwned Passwords named client. The host is not configurable.</summary>
    /// <param name="services">Service collection.</param>
    /// <returns>The service collection.</returns>
    public static IServiceCollection AddNovolisPwnedPasswordsClient(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.AddHttpClient(PwnedPasswordsApi.HttpClientName, client =>
        {
            client.BaseAddress = new Uri("https://api.pwnedpasswords.com/range/");
            client.DefaultRequestHeaders.TryAddWithoutValidation("Add-Padding", "true");
        });
        return services;
    }

    /// <summary>Adds the k-anonymity client and wires it into authentication registration.</summary>
    public static IServiceCollection AddNovolisPasswordBreachCheck(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.AddNovolisPwnedPasswordsClient();
        services.TryAddSingleton<IHaveIBeenPwnedClient, HaveIBeenPwnedClient>();
        services.TryAddSingleton<IPasswordBreachChecker, HaveIBeenPwnedPasswordBreachChecker>();
        return services;
    }
}
