using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Novolis.Http.Client;
using Novolis.Security.OAuth;

namespace Novolis.Security.OAuth.Client;

/// <summary>Acquires and caches access tokens through the private token client.</summary>
internal sealed class NovolisOAuthTokenAcquirer(
    IHttpClientFactory httpClientFactory,
    INovolisOAuthTokenCache cache,
    NovolisOAuthDiscovery discovery,
    NovolisOAuthDPoPKeyRegistry keys,
    DPoPProofCreator proofs,
    TimeProvider time,
    IServiceProvider services)
{
    private readonly ConcurrentDictionary<string, Lazy<Task<CachedOAuthAccessToken>>> _inflight = new(StringComparer.Ordinal);

    /// <summary>Returns a valid access token, acquiring or refreshing when needed.</summary>
    public async Task<CachedOAuthAccessToken> GetTokenAsync(
        string clientName,
        NovolisOAuthClientOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientName);
        ArgumentNullException.ThrowIfNull(options);
        var tokenEndpoint = await discovery.ResolveTokenEndpointAsync(options, cancellationToken);
        var cacheKey = string.Join('\u001f', clientName, tokenEndpoint, options.ClientId, options.Scope);
        if (cache.TryGet(cacheKey, out var existing) && existing is not null)
        {
            return existing;
        }

        var lazy = _inflight.GetOrAdd(
            cacheKey,
            key => new Lazy<Task<CachedOAuthAccessToken>>(() =>
                AcquireAsync(clientName, options, tokenEndpoint, key, cancellationToken)));
        try
        {
            return await lazy.Value;
        }
        finally
        {
            _inflight.TryRemove(new KeyValuePair<string, Lazy<Task<CachedOAuthAccessToken>>>(cacheKey, lazy));
        }
    }

    /// <summary>Exchanges an authorization code and stores the refresh token.</summary>
    public async Task ExchangeAuthorizationCodeAsync(
        string clientName,
        NovolisOAuthClientOptions options,
        string code,
        string codeVerifier,
        Uri redirectUri,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientName);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrWhiteSpace(code);
        ArgumentException.ThrowIfNullOrWhiteSpace(codeVerifier);
        ArgumentNullException.ThrowIfNull(redirectUri);
        var store = services.GetService<IRotatedRefreshTokenStore>()
            ?? throw new InvalidOperationException("A refresh-token store is required for authorization-code exchange.");
        var tokenEndpoint = await discovery.ResolveTokenEndpointAsync(options, cancellationToken);
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = OAuthGrantTypes.AuthorizationCode,
            ["code"] = code,
            ["redirect_uri"] = redirectUri.ToString(),
            ["client_id"] = options.ClientId,
            ["code_verifier"] = codeVerifier,
        };
        if (!string.IsNullOrWhiteSpace(options.ClientSecret))
        {
            form["client_secret"] = options.ClientSecret;
        }

        if (!string.IsNullOrWhiteSpace(options.Scope))
        {
            form["scope"] = options.Scope;
        }

        var response = await PostTokenAsync(options, clientName, tokenEndpoint, form, cancellationToken);
        if (string.IsNullOrWhiteSpace(response.RefreshToken))
        {
            throw new InvalidOperationException("Token endpoint did not return a refresh_token.");
        }

        await store.SetAsync(clientName, response.RefreshToken, cancellationToken);
        StoreAccessToken(clientName, options, tokenEndpoint, response);
    }

    /// <summary>Revokes <paramref name="token"/> at the issuer revocation endpoint.</summary>
    public async Task RevokeAsync(
        string clientName,
        NovolisOAuthClientOptions options,
        string token,
        string? tokenTypeHint,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientName);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrWhiteSpace(token);
        var endpoint = await discovery.ResolveRevocationEndpointAsync(options, cancellationToken);
        var form = new Dictionary<string, string>
        {
            ["token"] = token,
            ["client_id"] = options.ClientId,
        };
        if (!string.IsNullOrWhiteSpace(tokenTypeHint))
        {
            form["token_type_hint"] = tokenTypeHint;
        }

        if (!string.IsNullOrWhiteSpace(options.ClientSecret))
        {
            form["client_secret"] = options.ClientSecret;
        }

        using var message = new HttpRequestMessage(HttpMethod.Post, endpoint)
        {
            Content = new FormUrlEncodedContent(form),
        };
        AttachDPoP(message, options, clientName, accessToken: null);
        var client = httpClientFactory.CreateClient<NovolisOAuthTokenApi>();
        using var response = await client.SendAsync(message, cancellationToken);
        response.EnsureSuccessStatusCode();
        cache.Invalidate(clientName);
        var store = services.GetService<IRotatedRefreshTokenStore>();
        if (store is not null)
        {
            await store.ForgetAsync(clientName, cancellationToken);
        }
    }

    private async Task<CachedOAuthAccessToken> AcquireAsync(
        string clientName,
        NovolisOAuthClientOptions options,
        Uri tokenEndpoint,
        string cacheKey,
        CancellationToken cancellationToken)
    {
        Dictionary<string, string> form;
        if (options.UseRefresh)
        {
            var store = services.GetService<IRotatedRefreshTokenStore>()
                ?? throw new InvalidOperationException("A refresh-token store is required for refresh registrations.");
            var refreshToken = await store.GetAsync(clientName, cancellationToken);
            if (string.IsNullOrWhiteSpace(refreshToken))
            {
                throw new InvalidOperationException("A refresh token is required. This registration does not fall back to another grant.");
            }

            form = new Dictionary<string, string>
            {
                ["grant_type"] = OAuthGrantTypes.RefreshToken,
                ["refresh_token"] = refreshToken,
                ["client_id"] = options.ClientId,
            };
            if (!string.IsNullOrWhiteSpace(options.ClientSecret))
            {
                form["client_secret"] = options.ClientSecret;
            }

            if (!string.IsNullOrWhiteSpace(options.Scope))
            {
                form["scope"] = options.Scope;
            }
        }
        else
        {
            form = new Dictionary<string, string>
            {
                ["grant_type"] = OAuthGrantTypes.ClientCredentials,
                ["client_id"] = options.ClientId,
            };
            if (!string.IsNullOrWhiteSpace(options.ClientSecret))
            {
                form["client_secret"] = options.ClientSecret;
            }

            if (!string.IsNullOrWhiteSpace(options.Scope))
            {
                form["scope"] = options.Scope;
            }
        }

        var response = await PostTokenAsync(options, clientName, tokenEndpoint, form, cancellationToken);
        if (options.UseRefresh)
        {
            var store = services.GetRequiredService<IRotatedRefreshTokenStore>();
            if (!string.IsNullOrWhiteSpace(response.RefreshToken))
            {
                await store.SetAsync(clientName, response.RefreshToken, cancellationToken);
            }
        }

        return StoreAccessToken(clientName, options, tokenEndpoint, response);
    }

    private async Task<NovolisOAuthTokenResponse> PostTokenAsync(
        NovolisOAuthClientOptions options,
        string clientName,
        Uri tokenEndpoint,
        Dictionary<string, string> form,
        CancellationToken cancellationToken)
    {
        using var message = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint)
        {
            Content = new FormUrlEncodedContent(form),
        };
        AttachDPoP(message, options, clientName, accessToken: null);
        var client = httpClientFactory.CreateClient<NovolisOAuthTokenApi>();
        using var response = await client.SendAsync(message, cancellationToken);
        var body = await response.Content.ReadAsStringAsync(cancellationToken);
        NovolisOAuthTokenResponse tokenResponse;
        try
        {
            tokenResponse = JsonSerializer.Deserialize<NovolisOAuthTokenResponse>(body)
                ?? throw new InvalidOperationException("Token endpoint returned an empty or invalid JSON body.");
        }
        catch (JsonException) when (!response.IsSuccessStatusCode)
        {
            cache.Invalidate(clientName);
            response.EnsureSuccessStatusCode();
            throw;
        }

        if (string.Equals(tokenResponse.Error, "invalid_grant", StringComparison.OrdinalIgnoreCase))
        {
            cache.Invalidate(clientName);
            var store = services.GetService<IRotatedRefreshTokenStore>();
            if (store is not null)
            {
                await store.ForgetAsync(clientName, cancellationToken);
            }

            throw new InvalidOperationException("Token endpoint returned invalid_grant.");
        }

        if (!response.IsSuccessStatusCode)
        {
            cache.Invalidate(clientName);
            response.EnsureSuccessStatusCode();
        }

        if (string.IsNullOrWhiteSpace(tokenResponse.AccessToken))
        {
            throw new InvalidOperationException("Token endpoint returned an empty access_token.");
        }

        return tokenResponse;
    }

    private CachedOAuthAccessToken StoreAccessToken(
        string clientName,
        NovolisOAuthClientOptions options,
        Uri tokenEndpoint,
        NovolisOAuthTokenResponse response)
    {
        var stored = new CachedOAuthAccessToken
        {
            AccessToken = response.AccessToken!,
            TokenType = options.UseDPoP
                ? "DPoP"
                : string.IsNullOrWhiteSpace(response.TokenType) ? "Bearer" : response.TokenType,
            ExpiresAt = time.GetUtcNow().Add(NovolisOAuthTokenLifetime.FromExpiresIn(response.ExpiresIn)),
        };
        var cacheKey = string.Join('\u001f', clientName, tokenEndpoint, options.ClientId, options.Scope);
        cache.Set(clientName, cacheKey, stored);
        return stored;
    }

    private void AttachDPoP(
        HttpRequestMessage message,
        NovolisOAuthClientOptions options,
        string clientName,
        string? accessToken)
    {
        if (!options.UseDPoP)
        {
            return;
        }

        if (!keys.TryGet(clientName, out var key) || key is null)
        {
            throw new InvalidOperationException($"No DPoP signing key is registered for {clientName}.");
        }

        var uri = message.RequestUri?.ToString()
            ?? throw new InvalidOperationException("Token requests require an absolute URI.");
        var proof = proofs.Create(key, message.Method.Method, uri, accessToken, time);
        message.Headers.Remove("DPoP");
        message.Headers.TryAddWithoutValidation("DPoP", proof);
        if (accessToken is not null)
        {
            message.Headers.Authorization = new AuthenticationHeaderValue("DPoP", accessToken);
        }
    }
}
