namespace Novolis.Security.Authentication;

/// <summary>No-op authentication event sink.</summary>
public sealed class NoopAuthenticationEventSink : IAuthenticationEventSink
{
    /// <summary>Shared stateless instance.</summary>
    public static NoopAuthenticationEventSink Instance { get; } = new();

    /// <inheritdoc />
    public ValueTask RecordAsync(
        AuthenticationSecurityEvent securityEvent,
        CancellationToken cancellationToken = default) =>
        ValueTask.CompletedTask;
}
