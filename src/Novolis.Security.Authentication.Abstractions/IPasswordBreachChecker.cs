namespace Novolis.Security.Authentication;

/// <summary>Host-supplied check against a breached-password corpus. Authentication never calls a network API itself.</summary>
public interface IPasswordBreachChecker
{
    /// <summary>Returns true when <paramref name="password"/> appears in a breach corpus.</summary>
    ValueTask<bool> IsBreachedAsync(string password, CancellationToken cancellationToken = default);
}
