namespace Novolis.Security.Authorization;

/// <summary>Default authorization event sink.</summary>
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
