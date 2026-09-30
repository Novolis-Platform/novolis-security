using Microsoft.Extensions.DependencyInjection;

namespace Novolis.Security.Authentication;

/// <summary>Fluent composition returned by the high-level authentication façade.</summary>
public sealed class NovolisSecurityBuilder
{
    /// <summary>Creates the builder.</summary>
    public NovolisSecurityBuilder(IServiceCollection services)
    {
        Services = services;
    }

    /// <summary>The service collection being composed.</summary>
    public IServiceCollection Services { get; }
}
