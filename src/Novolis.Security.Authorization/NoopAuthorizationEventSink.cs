namespace Novolis.Security.Authorization;

/// <summary>Explicit no-op authorization event sink. The library default is <c>LoggerAuthorizationEventSink</c>.</summary>
public sealed class NoopAuthorizationEventSink : IAuthorizationEventSink
{
    /// <summary>Shared instance.</summary>
    public static NoopAuthorizationEventSink Instance { get; } = new();

    /// <inheritdoc />
    public ValueTask RecordAsync(
        AuthorizationSecurityEvent securityEvent,
        CancellationToken cancellationToken = default) =>
        ValueTask.CompletedTask;
}
