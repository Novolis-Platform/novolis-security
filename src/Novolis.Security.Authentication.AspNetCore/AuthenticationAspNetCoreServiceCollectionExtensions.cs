using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Novolis.Security.Authentication;
using Novolis.Security.OAuth;
using Novolis.Security.OAuth.AspNetCore;
using AuthenticationCore = Novolis.Security.Authentication.AuthenticationServiceCollectionExtensions;

namespace Novolis.Security.Authentication.AspNetCore;

/// <summary>High-level ASP.NET Core authentication composition.</summary>
public static class AuthenticationAspNetCoreServiceCollectionExtensions
{
    /// <summary>
    /// Adds identity resolution, credential verification, browser sessions, and the OAuth protocol surface.
    /// </summary>
    public static NovolisSecurityBuilder AddNovolisAuthentication(
        this IServiceCollection services,
        Action<AuthenticationOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        AuthenticationCore.AddNovolisAuthentication(services, configure);
        services.AddOptions<OAuthOptions>()
            .Configure<IOptions<AuthenticationOptions>>((oauth, authentication) =>
            {
                if (authentication.Value.Issuer is not null)
                    oauth.Issuer = authentication.Value.Issuer;
            });
        OAuthAspNetCoreServiceCollectionExtensions.AddNovolisOAuth(services);
        return new NovolisSecurityBuilder(services);
    }
}

