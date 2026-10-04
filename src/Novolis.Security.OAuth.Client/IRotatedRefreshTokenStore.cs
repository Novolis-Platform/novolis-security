namespace Novolis.Security.OAuth.Client;

/// <summary>Host-owned store for the latest refresh token of a named outbound client.</summary>
public interface IRotatedRefreshTokenStore
{
    /// <summary>Returns the current refresh token for <paramref name="clientName"/>.</summary>
    /// <param name="clientName">Factory name of the resource client.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The stored refresh token, or <see langword="null"/> when none is stored.</returns>
    ValueTask<string?> GetAsync(string clientName, CancellationToken cancellationToken = default);

    /// <summary>Replaces the refresh token for <paramref name="clientName"/>.</summary>
    /// <param name="clientName">Factory name of the resource client.</param>
    /// <param name="refreshToken">Latest refresh token.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task that completes when the token is stored.</returns>
    ValueTask SetAsync(string clientName, string refreshToken, CancellationToken cancellationToken = default);

    /// <summary>Forgets the refresh token for <paramref name="clientName"/>.</summary>
    /// <param name="clientName">Factory name of the resource client.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task that completes when the token is removed.</returns>
    ValueTask ForgetAsync(string clientName, CancellationToken cancellationToken = default);
}
