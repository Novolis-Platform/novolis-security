namespace Novolis.Security.Authorization;

/// <summary>
/// Best-effort authorization observation sink.
/// The library default writes identifiers to <c>ILogger</c> and never includes secrets.
/// </summary>
public interface IAuthorizationEventSink
{
    /// <summary>Records a non-secret authorization event.</summary>
    ValueTask RecordAsync(
        AuthorizationSecurityEvent securityEvent,
        CancellationToken cancellationToken = default);
}
