using Novolis.Http.Client;

namespace Novolis.Security.OAuth.Client;

/// <summary>Sends through the named resource client registered for <typeparamref name="TApi"/>.</summary>
/// <typeparam name="TApi">Client key.</typeparam>
internal sealed class NovolisOAuthClient<TApi>(IHttpClientFactory factory) : INovolisOAuthClient<TApi>
    where TApi : OAuthClientKey, new()
{
    /// <inheritdoc />
    public Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        return factory.CreateClient<TApi>().SendAsync(request, cancellationToken);
    }
}
