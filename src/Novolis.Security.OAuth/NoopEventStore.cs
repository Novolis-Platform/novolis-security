namespace Novolis.Security.OAuth;

/// <summary>Explicit no-op event sink. The library default is <c>LoggerEventStore</c>; production still refuses this type unless <c>AllowInMemoryStores</c> is set.</summary>
public sealed class NoopEventStore : IEventStore
{
    /// <summary>Shared instance.</summary>
    public static NoopEventStore Instance { get; } = new();

    /// <inheritdoc />
    public ValueTask RecordAsync(SecurityEvent evt, CancellationToken ct = default) => ValueTask.CompletedTask;
}
