namespace Novolis.Security.Authentication;

/// <summary>Default second factor that always succeeds. Products replace this with a real <see cref="IMfaProvider"/>.</summary>
public sealed class NoopMfaProvider : IMfaProvider
{
    /// <summary>Shared instance.</summary>
    public static NoopMfaProvider Instance { get; } = new();

    /// <inheritdoc />
    public ValueTask<MfaDecision> CompleteAsync(
        MfaContext context,
        ICacheStore cache,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(cache);
        return ValueTask.FromResult(MfaDecision.Ok());
    }
}
