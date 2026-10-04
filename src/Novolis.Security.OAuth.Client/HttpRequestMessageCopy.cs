namespace Novolis.Security.OAuth.Client;

/// <summary>Copies a request so a 401 retry can send it again.</summary>
internal static class HttpRequestMessageCopy
{
    /// <summary>Creates a new request with the same method, URI, headers, and body.</summary>
    public static HttpRequestMessage Copy(
        HttpRequestMessage request,
        byte[]? body,
        CancellationToken cancellationToken)
    {
        var copy = new HttpRequestMessage(request.Method, request.RequestUri)
        {
            Version = request.Version,
            VersionPolicy = request.VersionPolicy,
        };
        foreach (var header in request.Headers)
        {
            copy.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }

        if (body is not null)
        {
            var content = new ByteArrayContent(body);
            if (request.Content is not null)
            {
                foreach (var header in request.Content.Headers)
                {
                    content.Headers.TryAddWithoutValidation(header.Key, header.Value);
                }
            }

            copy.Content = content;
        }

        foreach (var option in request.Options)
        {
            copy.Options.TryAdd(option.Key, option.Value);
        }

        cancellationToken.ThrowIfCancellationRequested();
        return copy;
    }

    /// <summary>Reads the request body so it can be attached to each send.</summary>
    public static async Task<byte[]?> ReadBodyAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        if (request.Content is null)
        {
            return null;
        }

        return await request.Content.ReadAsByteArrayAsync(cancellationToken);
    }
}
