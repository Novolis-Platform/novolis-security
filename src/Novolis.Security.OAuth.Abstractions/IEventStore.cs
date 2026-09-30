using Novolis.Security.Authentication;

namespace Novolis.Security.OAuth;

/// <summary>
/// Observation surface for token-service outcomes. The default is a no-op.
/// Payloads never include passwords, refresh secrets, PEMs, or hashes — turn this on to watch grants, not to log credentials.
/// Distinct from <c>Novolis.Storage.Abstractions.Events.IEventStore</c> (append-only journal).
/// </summary>
public interface IEventStore
{
    /// <summary>Records one observation. Implementations must not throw into the token path.</summary>
    ValueTask RecordAsync(SecurityEvent evt, CancellationToken ct = default);
}
