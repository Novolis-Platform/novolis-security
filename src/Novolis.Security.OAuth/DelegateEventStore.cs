namespace Novolis.Security.OAuth;

/// <summary>Event sink that forwards observations to a host delegate.</summary>
public sealed class DelegateEventStore(Func<SecurityEvent, CancellationToken, ValueTask> handler) : IEventStore
{
    /// <inheritdoc />
    public ValueTask RecordAsync(SecurityEvent evt, CancellationToken ct = default) =>
        handler(evt, ct);
}
