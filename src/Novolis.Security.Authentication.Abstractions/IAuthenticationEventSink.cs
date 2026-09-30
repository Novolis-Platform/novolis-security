namespace Novolis.Security.Authentication;

/// <summary>Best-effort structured authentication event sink.</summary>
public interface IAuthenticationEventSink
{
    /// <summary>Records an event without placing secrets in the payload.</summary>
    ValueTask RecordAsync(
        AuthenticationSecurityEvent securityEvent,
        CancellationToken cancellationToken = default);
}
