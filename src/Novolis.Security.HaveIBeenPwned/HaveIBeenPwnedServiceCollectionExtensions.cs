using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Novolis.Security.Authentication;

namespace Novolis.Security.HaveIBeenPwned;

/// <summary>Registers the Have I Been Pwned range client as an <see cref="IPasswordBreachChecker"/>.</summary>
public static class HaveIBeenPwnedServiceCollectionExtensions
{
    /// <summary>Adds the k-anonymity client and wires it into authentication registration.</summary>
    public static IServiceCollection AddNovolisPasswordBreachCheck(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.AddHttpClient();
        services.TryAddSingleton<IHaveIBeenPwnedClient, HaveIBeenPwnedClient>();
        services.TryAddSingleton<IPasswordBreachChecker, HaveIBeenPwnedPasswordBreachChecker>();
        return services;
    }
}
