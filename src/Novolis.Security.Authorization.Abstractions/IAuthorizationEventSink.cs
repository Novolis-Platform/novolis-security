namespace Novolis.Security.Authorization;

/// <summary>Best-effort authorization observation sink.</summary>
public interface IAuthorizationEventSink
{
    /// <summary>Records a non-secret authorization event.</summary>
    ValueTask RecordAsync(
        AuthorizationSecurityEvent securityEvent,
        CancellationToken cancellationToken = default);
}
