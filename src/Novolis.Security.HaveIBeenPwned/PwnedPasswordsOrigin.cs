namespace Novolis.Security.HaveIBeenPwned;

/// <summary>Pins Pwned Passwords range requests to api.pwnedpasswords.com over HTTPS.</summary>
internal static class PwnedPasswordsOrigin
{
    /// <summary>Creates the primary handler. Redirects are off so a 30x cannot move the SHA-1 prefix.</summary>
    public static HttpMessageHandler CreatePrimaryHandler() =>
        new HttpClientHandler { AllowAutoRedirect = false };

    /// <summary>Throws when <paramref name="address"/> is not the pinned range origin.</summary>
    public static void EnsurePinned(Uri? address)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (!string.Equals(address.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(address.Host, HaveIBeenPwnedClient.AllowedPwnedPasswordsHost, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "Pwned Passwords requests must use https://" + HaveIBeenPwnedClient.AllowedPwnedPasswordsHost + ".");
        }
    }
}
