namespace Novolis.Security.OAuth.Client;

/// <summary>Accepts absolute HTTPS URIs, or HTTP when the host is loopback.</summary>
internal static class NovolisOAuthUriRules
{
    /// <summary>Returns whether <paramref name="uri"/> is an allowed issuer, resource, or token address.</summary>
    public static bool IsAllowed(Uri? uri)
    {
        if (uri is null || !uri.IsAbsoluteUri)
        {
            return false;
        }

        if (string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) && uri.IsLoopback;
    }

    /// <summary>Throws when <paramref name="uri"/> is not allowed.</summary>
    /// <param name="uri">Address to check.</param>
    /// <param name="name">Parameter name used in the exception.</param>
    public static void ThrowIfDisallowed(Uri uri, string name)
    {
        ArgumentNullException.ThrowIfNull(uri);
        if (!IsAllowed(uri))
        {
            throw new ArgumentException(
                $"{name} must be an absolute https URI. Loopback http is allowed.",
                name);
        }
    }
}
