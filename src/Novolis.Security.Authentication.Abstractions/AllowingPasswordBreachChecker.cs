namespace Novolis.Security.Authentication;

/// <summary>Development and test checker that never reports a breach.</summary>
public sealed class AllowingPasswordBreachChecker : IPasswordBreachChecker
{
    /// <summary>Shared instance.</summary>
    public static AllowingPasswordBreachChecker Instance { get; } = new();

    /// <inheritdoc />
    public ValueTask<bool> IsBreachedAsync(
        string password,
        CancellationToken cancellationToken = default) =>
        ValueTask.FromResult(false);
}
