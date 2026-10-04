namespace Novolis.Security.HaveIBeenPwned;

/// <summary>Rejects range requests that leave the pinned Pwned Passwords host.</summary>
internal sealed class PwnedPasswordsPinHandler : DelegatingHandler
{
    /// <inheritdoc />
    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        PwnedPasswordsOrigin.EnsurePinned(request.RequestUri);
        return base.SendAsync(request, cancellationToken);
    }
}
