using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Novolis.Security.Idp;

namespace Novolis.Security.Idp.AspNetCore;

/// <summary>Registers IDP services, token-endpoint rate limiting, and in-process JWT bearer validation.</summary>
public static class IdpAspNetCoreServiceCollectionExtensions
{
    /// <summary>Policy name applied to <c>POST /oauth/token</c>.</summary>
    public const string TokenRateLimitPolicy = "idp-token";

    /// <summary>Adds <see cref="IdpServiceCollectionExtensions.AddNovolisIdp"/> plus a fixed-window limiter on the token endpoint.</summary>
    public static IServiceCollection AddNovolisIdp(
        this IServiceCollection services,
        Action<IdpOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        IdpServiceCollectionExtensions.AddNovolisIdp(services, configure);
        services.AddOptions<IdpOptions>()
            .Configure<IHostEnvironment>((options, env) => options.IsDevelopment = env.IsDevelopment());
        services.AddRateLimiter(limiter =>
        {
            limiter.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            limiter.AddPolicy(TokenRateLimitPolicy, httpContext =>
            {
                // Partition by IP only. Never read the form here — malformed bodies
                // (null bytes) must not 500 in the limiter before the endpoint runs.
                var ip = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
                return RateLimitPartition.GetFixedWindowLimiter(
                    ip,
                    _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = 30,
                        Window = TimeSpan.FromMinutes(1),
                        QueueLimit = 0,
                    });
            });
        });
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
            .Configure<IdpTokenService>((options, idp) =>
            {
                options.MapInboundClaims = false;
                options.TokenValidationParameters = idp.CreateValidationParameters();
            });
        return builder;
    }
}
