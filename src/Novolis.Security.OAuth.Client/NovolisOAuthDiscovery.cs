using System.Collections.Concurrent;
using System.Text.Json;
using Novolis.Http.Client;

namespace Novolis.Security.OAuth.Client;

/// <summary>Reads RFC 8414 metadata through the private token client.</summary>
internal sealed class NovolisOAuthDiscovery(IHttpClientFactory httpClientFactory)
{
    private readonly ConcurrentDictionary<string, NovolisOAuthDiscoveryDocument> _cache = new(StringComparer.Ordinal);

    /// <summary>Returns token and revocation endpoints for <paramref name="issuer"/>.</summary>
    public async Task<NovolisOAuthDiscoveryDocument> GetAsync(Uri issuer, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        var origin = issuer.ToString().TrimEnd('/');
        if (_cache.TryGetValue(origin, out var cached))
        {
            return cached;
        }

        var metadata = new Uri(origin + "/.well-known/oauth-authorization-server");
        var client = httpClientFactory.CreateClient<NovolisOAuthTokenApi>();
        using var response = await client.GetAsync(metadata, cancellationToken);
        response.EnsureSuccessStatusCode();
        var body = await response.Content.ReadAsStringAsync(cancellationToken);
        var document = JsonSerializer.Deserialize<NovolisOAuthDiscoveryDocument>(body)
            ?? throw new InvalidOperationException("Issuer metadata was empty.");
        if (string.IsNullOrWhiteSpace(document.TokenEndpoint))
        {
            throw new InvalidOperationException("Issuer metadata did not include token_endpoint.");
        }

        _cache[origin] = document;
        return document;
    }

    /// <summary>Resolves the token endpoint from options or discovery.</summary>
    public async Task<Uri> ResolveTokenEndpointAsync(
        NovolisOAuthClientOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (options.TokenEndpoint is not null)
        {
            return options.TokenEndpoint;
        }

        var document = await GetAsync(options.Issuer, cancellationToken);
        return new Uri(document.TokenEndpoint!);
    }

    /// <summary>Resolves the revocation endpoint from discovery, or <c>{issuer}/oauth/revoke</c>.</summary>
    public async Task<Uri> ResolveRevocationEndpointAsync(
        NovolisOAuthClientOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (options.TokenEndpoint is not null)
        {
            return new Uri(options.Issuer.ToString().TrimEnd('/') + "/oauth/revoke");
        }

        var document = await GetAsync(options.Issuer, cancellationToken);
        if (!string.IsNullOrWhiteSpace(document.RevocationEndpoint))
        {
            return new Uri(document.RevocationEndpoint);
        }

        return new Uri(options.Issuer.ToString().TrimEnd('/') + "/oauth/revoke");
    }
}
