namespace Novolis.Security.Authentication;

/// <summary>
/// Best-effort structured authentication event sink.
/// The library default writes identifiers to <c>ILogger</c> and never includes passwords or hashes.
/// </summary>
public interface IAuthenticationEventSink
{
    /// <summary>Records an event without placing secrets in the payload.</summary>
    ValueTask RecordAsync(
        AuthenticationSecurityEvent securityEvent,
        CancellationToken cancellationToken = default);
}
