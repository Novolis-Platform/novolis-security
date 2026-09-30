using Novolis.Security.Authentication;

namespace Novolis.Security.HaveIBeenPwned;

/// <summary>Have I Been Pwned adapter for <see cref="IPasswordBreachChecker"/>.</summary>
public sealed class HaveIBeenPwnedPasswordBreachChecker(IHaveIBeenPwnedClient client) : IPasswordBreachChecker
{
    /// <inheritdoc />
    public async ValueTask<bool> IsBreachedAsync(
        string password,
        CancellationToken cancellationToken = default) =>
        await client.IsPwnedAsync(password).ConfigureAwait(false);
}
