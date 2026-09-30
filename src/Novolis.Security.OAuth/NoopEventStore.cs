namespace Novolis.Security.OAuth;

/// <summary>Default event sink. Records nothing. Replace with a recording or queued implementation to observe grants.</summary>
public sealed class NoopEventStore : IEventStore
{
    /// <summary>Shared instance.</summary>
    public static NoopEventStore Instance { get; } = new();

    /// <inheritdoc />
    public ValueTask RecordAsync(SecurityEvent evt, CancellationToken ct = default) => ValueTask.CompletedTask;
}
