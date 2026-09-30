using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Novolis.Security.OAuth;

namespace Novolis.Security.OAuth.AspNetCore;

/// <summary>Registers OAuth protocol services and resource-server token validation.</summary>
public static class OAuthAspNetCoreServiceCollectionExtensions
{
    /// <summary>Adds the OAuth core and development-aware defaults.</summary>
    public static IServiceCollection AddNovolisOAuth(
        this IServiceCollection services,
        Action<OAuthOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        OAuthServiceCollectionExtensions.AddNovolisOAuth(services, configure);
        services.AddOptions<OAuthOptions>()
            .Configure<IHostEnvironment>((options, env) => options.IsDevelopment = env.IsDevelopment());
        return services;
    }

    /// <summary>Configures in-process validation against this token mint's key ring.</summary>
    public static Microsoft.AspNetCore.Authentication.AuthenticationBuilder AddNovolisJwtBearer(
        this Microsoft.AspNetCore.Authentication.AuthenticationBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.AddJwtBearer();
        builder.Services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
            .Configure<OAuthTokenService>((options, tokens) =>
            {
                options.MapInboundClaims = false;
                options.TokenValidationParameters = tokens.CreateValidationParameters();
            });
        return builder;
    }

    /// <summary>
    /// Configures a resource server to discover issuer metadata and JWKS from an OAuth authority.
    /// </summary>
    public static AuthenticationBuilder AddNovolisBearer(
        this AuthenticationBuilder builder,
        Uri issuer,
        string audience)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentException.ThrowIfNullOrEmpty(audience);

        builder.AddJwtBearer(options =>
        {
            var authority = issuer.ToString().TrimEnd('/');
            options.Authority = authority;
            options.MetadataAddress = authority + "/.well-known/oauth-authorization-server";
            options.Audience = audience;
            options.MapInboundClaims = false;
            options.RequireHttpsMetadata = !issuer.IsLoopback;
            options.TokenValidationParameters.ValidAlgorithms =
                [Microsoft.IdentityModel.Tokens.SecurityAlgorithms.EcdsaSha384];
        });
        return builder;
    }
}
