using Microsoft.Extensions.Options;
using Novolis.Http.Client;

namespace Novolis.Security.OAuth.Client;

/// <summary>Resource client plus authorization-code exchange and revocation.</summary>
/// <typeparam name="TApi">Client key.</typeparam>
internal sealed class NovolisOAuthRefreshClient<TApi>(
    IHttpClientFactory factory,
    IOptionsMonitor<NovolisOAuthClientOptions> options,
    NovolisOAuthTokenAcquirer acquirer) : INovolisOAuthRefreshClient<TApi>
    where TApi : OAuthClientKey, new()
{
    /// <inheritdoc />
    public Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        return factory.CreateClient<TApi>().SendAsync(request, cancellationToken);
    }

    /// <inheritdoc />
    public Task ExchangeAuthorizationCodeAsync(
        string code,
        string codeVerifier,
        Uri redirectUri,
        CancellationToken cancellationToken = default)
    {
        var clientName = HttpClientKey.For<TApi>();
        return acquirer.ExchangeAuthorizationCodeAsync(
            clientName,
            options.Get(clientName),
            code,
            codeVerifier,
            redirectUri,
            cancellationToken);
    }

    /// <inheritdoc />
    public Task RevokeAsync(string token, string? tokenTypeHint = null, CancellationToken cancellationToken = default)
    {
        var clientName = HttpClientKey.For<TApi>();
        return acquirer.RevokeAsync(clientName, options.Get(clientName), token, tokenTypeHint, cancellationToken);
    }
}
