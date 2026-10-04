using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Novolis.Http.Client;

namespace Novolis.Security.OAuth.Client;

/// <summary>Closed DI registration for outbound Novolis OAuth resource clients.</summary>
public static class NovolisOAuthClientServiceCollectionExtensions
{
    /// <summary>Registers a Novolis issuer client for the client-credentials grant.</summary>
    /// <typeparam name="TApi">Client key. Not registered in dependency injection.</typeparam>
    /// <param name="services">Service collection.</param>
    /// <param name="baseAddress">Resource API base address.</param>
    /// <param name="credential">Confidential or DPoP client-credentials credential.</param>
    /// <param name="primaryHandler">Optional test seam. Not an <see cref="IHttpClientBuilder"/>.</param>
    /// <returns>The service collection.</returns>
    public static IServiceCollection AddNovolisOAuthClient<TApi>(
        this IServiceCollection services,
        Uri baseAddress,
        ClientCredentialsCredential credential,
        HttpMessageHandler? primaryHandler = null)
        where TApi : OAuthClientKey, new()
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(credential);
        ValidateAddresses(baseAddress, credential.Issuer, credential.TokenEndpoint);
        ArgumentException.ThrowIfNullOrWhiteSpace(credential.ClientId);
        ArgumentException.ThrowIfNullOrWhiteSpace(credential.Scope);
        AddSharedServices(services, primaryHandler);
        var clientName = HttpClientKey.For<TApi>();
        RegisterDPoPKey(services, clientName, credential.DPoPSigningKey);
        ConfigureClient<TApi>(
            services,
            baseAddress,
            credential.Issuer,
            credential.ClientId,
            credential.Scope,
            credential.ClientSecret,
            credential.TokenEndpoint,
            useDPoP: credential.DPoPSigningKey is not null,
            useRefresh: false,
            primaryHandler);
        services.TryAddSingleton<INovolisOAuthClient<TApi>, NovolisOAuthClient<TApi>>();
        return services;
    }

    /// <summary>Registers a Novolis issuer client for the refresh-token grant.</summary>
    /// <typeparam name="TApi">Client key. Not registered in dependency injection.</typeparam>
    /// <typeparam name="TStore">Host refresh-token store. Must already be registered.</typeparam>
    /// <param name="services">Service collection.</param>
    /// <param name="baseAddress">Resource API base address.</param>
    /// <param name="credential">Confidential or DPoP refresh credential.</param>
    /// <param name="primaryHandler">Optional test seam. Not an <see cref="IHttpClientBuilder"/>.</param>
    /// <returns>The service collection.</returns>
    public static IServiceCollection AddNovolisOAuthClient<TApi, TStore>(
        this IServiceCollection services,
        Uri baseAddress,
        RefreshCredential credential,
        HttpMessageHandler? primaryHandler = null)
        where TApi : OAuthClientKey, new()
        where TStore : class, IRotatedRefreshTokenStore
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(credential);
        ValidateAddresses(baseAddress, credential.Issuer, credential.TokenEndpoint);
        ArgumentException.ThrowIfNullOrWhiteSpace(credential.ClientId);
        ArgumentException.ThrowIfNullOrWhiteSpace(credential.Scope);
        if (!services.Any(descriptor => descriptor.ServiceType == typeof(TStore)))
        {
            throw new InvalidOperationException(
                $"{typeof(TStore).Name} must be registered before AddNovolisOAuthClient<{typeof(TApi).Name}, {typeof(TStore).Name}>().");
        }

        AddSharedServices(services, primaryHandler);
        services.TryAddSingleton<IRotatedRefreshTokenStore>(provider => provider.GetRequiredService<TStore>());
        var clientName = HttpClientKey.For<TApi>();
        RegisterDPoPKey(services, clientName, credential.DPoPSigningKey);
        ConfigureClient<TApi>(
            services,
            baseAddress,
            credential.Issuer,
            credential.ClientId,
            credential.Scope,
            credential.ClientSecret,
            credential.TokenEndpoint,
            useDPoP: credential.DPoPSigningKey is not null,
            useRefresh: true,
            primaryHandler);
        services.TryAddSingleton<INovolisOAuthClient<TApi>, NovolisOAuthClient<TApi>>();
        services.TryAddSingleton<INovolisOAuthRefreshClient<TApi>, NovolisOAuthRefreshClient<TApi>>();
        return services;
    }

    private static void AddSharedServices(IServiceCollection services, HttpMessageHandler? primaryHandler)
    {
        services.AddNovolisHttp();
        services.TryAddSingleton(TimeProvider.System);
        services.AddMemoryCache();
        services.TryAddSingleton<INovolisOAuthTokenCache, NovolisOAuthTokenCache>();
        services.TryAddSingleton<NovolisOAuthDPoPKeyRegistry>(provider =>
        {
            var registry = new NovolisOAuthDPoPKeyRegistry();
            foreach (var binding in provider.GetServices<INovolisOAuthDPoPKeyBinding>())
            {
                binding.Apply(registry);
            }

            return registry;
        });
        services.TryAddSingleton<DPoPProofCreator>();
        services.TryAddSingleton<NovolisOAuthDiscovery>();
        services.TryAddSingleton<NovolisOAuthTokenAcquirer>();
        var token = services.AddHttpClientFor<NovolisOAuthTokenApi>();
        if (primaryHandler is not null)
        {
            token.ConfigurePrimaryHttpMessageHandler(() => primaryHandler);
        }
    }

    private static void ConfigureClient<TApi>(
        IServiceCollection services,
        Uri baseAddress,
        Uri issuer,
        string clientId,
        string scope,
        string? clientSecret,
        Uri? tokenEndpoint,
        bool useDPoP,
        bool useRefresh,
        HttpMessageHandler? primaryHandler)
        where TApi : OAuthClientKey, new()
    {
        var clientName = HttpClientKey.For<TApi>();
        services.AddOptions<NovolisOAuthClientOptions>(clientName)
            .Configure(options =>
            {
                options.BaseAddress = baseAddress;
                options.Issuer = issuer;
                options.ClientId = clientId;
                options.Scope = scope;
                options.ClientSecret = clientSecret;
                options.TokenEndpoint = tokenEndpoint;
                options.UseDPoP = useDPoP;
                options.UseRefresh = useRefresh;
            })
            .Validate(options => NovolisOAuthUriRules.IsAllowed(options.Issuer), "Issuer must be an absolute https URI. Loopback http is allowed.")
            .Validate(options => NovolisOAuthUriRules.IsAllowed(options.BaseAddress), "Base address must be an absolute https URI. Loopback http is allowed.")
            .Validate(options => !string.IsNullOrWhiteSpace(options.ClientId), "ClientId is required.")
            .Validate(options => !string.IsNullOrWhiteSpace(options.Scope), "Scope is required.")
            .Validate(
                options => options.TokenEndpoint is null || NovolisOAuthUriRules.IsAllowed(options.TokenEndpoint),
                "Token endpoint must be an absolute https URI. Loopback http is allowed.")
            .ValidateOnStart();

        var builder = services.AddHttpClientFor<TApi>(client => client.BaseAddress = baseAddress);
        if (primaryHandler is not null)
        {
            builder.ConfigurePrimaryHttpMessageHandler(() => primaryHandler);
        }

        builder.AddHttpMessageHandler(provider =>
            new NovolisOAuthAuthenticationHandler(
                provider.GetRequiredService<IOptionsMonitor<NovolisOAuthClientOptions>>(),
                provider.GetRequiredService<NovolisOAuthTokenAcquirer>(),
                provider.GetRequiredService<INovolisOAuthTokenCache>(),
                provider.GetRequiredService<NovolisOAuthDPoPKeyRegistry>(),
                provider.GetRequiredService<DPoPProofCreator>(),
                provider.GetRequiredService<TimeProvider>(),
                clientName));
    }

    private static void RegisterDPoPKey(IServiceCollection services, string clientName, System.Security.Cryptography.ECDsa? key)
    {
        if (key is null)
        {
            return;
        }

        services.AddSingleton<INovolisOAuthDPoPKeyBinding>(new NovolisOAuthDPoPKeyBinding(clientName, key));
    }

    private static void ValidateAddresses(Uri baseAddress, Uri issuer, Uri? tokenEndpoint)
    {
        NovolisOAuthUriRules.ThrowIfDisallowed(baseAddress, nameof(baseAddress));
        NovolisOAuthUriRules.ThrowIfDisallowed(issuer, nameof(issuer));
        if (tokenEndpoint is not null)
        {
            NovolisOAuthUriRules.ThrowIfDisallowed(tokenEndpoint, nameof(tokenEndpoint));
        }
    }
}
