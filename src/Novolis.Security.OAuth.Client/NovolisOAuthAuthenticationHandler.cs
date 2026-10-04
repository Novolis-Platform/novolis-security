using System.Net;
using System.Net.Http.Headers;
using Microsoft.Extensions.Options;

namespace Novolis.Security.OAuth.Client;

/// <summary>Attaches a cached Novolis access token and retries a 401 once.</summary>
internal sealed class NovolisOAuthAuthenticationHandler(
    IOptionsMonitor<NovolisOAuthClientOptions> options,
    NovolisOAuthTokenAcquirer acquirer,
    INovolisOAuthTokenCache cache,
    NovolisOAuthDPoPKeyRegistry keys,
    DPoPProofCreator proofs,
    TimeProvider time,
    string clientName) : DelegatingHandler
{
    /// <inheritdoc />
    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var settings = options.Get(clientName);
        var body = await HttpRequestMessageCopy.ReadBodyAsync(request, cancellationToken);
        var first = await SendOnceAsync(request, body, settings, cancellationToken);
        if (first.StatusCode != HttpStatusCode.Unauthorized)
        {
            return first;
        }

        first.Dispose();
        cache.Invalidate(clientName);
        return await SendOnceAsync(request, body, settings, cancellationToken);
    }

    private async Task<HttpResponseMessage> SendOnceAsync(
        HttpRequestMessage request,
        byte[]? body,
        NovolisOAuthClientOptions settings,
        CancellationToken cancellationToken)
    {
        var token = await acquirer.GetTokenAsync(clientName, settings, cancellationToken);
        var outgoing = HttpRequestMessageCopy.Copy(request, body, cancellationToken);
        outgoing.Headers.Authorization = new AuthenticationHeaderValue(token.TokenType, token.AccessToken);
        if (settings.UseDPoP)
        {
            if (!keys.TryGet(clientName, out var key) || key is null)
            {
                throw new InvalidOperationException($"No DPoP signing key is registered for {clientName}.");
            }

            var uri = outgoing.RequestUri?.ToString()
                ?? throw new InvalidOperationException("Resource requests require a URI.");
            var proof = proofs.Create(key, outgoing.Method.Method, uri, token.AccessToken, time);
            outgoing.Headers.Remove("DPoP");
            outgoing.Headers.TryAddWithoutValidation("DPoP", proof);
        }

        return await base.SendAsync(outgoing, cancellationToken);
    }
}
