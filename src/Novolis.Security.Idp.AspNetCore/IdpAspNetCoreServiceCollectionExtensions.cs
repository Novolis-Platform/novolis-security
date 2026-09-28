using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Novolis.Security.Idp;

namespace Novolis.Security.Idp.AspNetCore;

/// <summary>Registers identity services and in-process JWT bearer validation. Edge IP limits stay on the host.</summary>
public static class IdpAspNetCoreServiceCollectionExtensions
{
    /// <summary>Adds <see cref="IdpServiceCollectionExtensions.AddNovolisIdp"/>. Attempt limits use <see cref="ICacheStore"/>, not ASP.NET RateLimiter.</summary>
    public static IServiceCollection AddNovolisIdp(
        this IServiceCollection services,
        Action<IdpOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        IdpServiceCollectionExtensions.AddNovolisIdp(services, configure);
        services.AddOptions<IdpOptions>()
            .Configure<IHostEnvironment>((options, env) => options.IsDevelopment = env.IsDevelopment());
        return services;
    }

    /// <summary>
    /// JwtBearer that validates ES384 tokens with this process's <see cref="IdpTokenService"/>.
    /// Split-host APIs should set <c>Authority</c> on JwtBearerOptions instead.
    /// </summary>
    public static Microsoft.AspNetCore.Authentication.AuthenticationBuilder AddNovolisJwtBearer(
        this Microsoft.AspNetCore.Authentication.AuthenticationBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.AddJwtBearer();
        builder.Services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
            .Configure<IdpTokenService>((options, tokens) =>
            {
                options.MapInboundClaims = false;
                options.TokenValidationParameters = tokens.CreateValidationParameters();
            });
        return builder;
    }
}
