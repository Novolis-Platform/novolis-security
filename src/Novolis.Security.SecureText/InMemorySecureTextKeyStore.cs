using System.Security.Cryptography;

namespace Novolis.Security.SecureText;

/// <summary>Process-local identity storage for tests and short-lived hosts only.</summary>
public sealed class InMemorySecureTextKeyStore : ISecureTextKeyStore
{
    private readonly Dictionary<string, SecureTextDeviceIdentity> _identities = new(StringComparer.Ordinal);
    private readonly Lock _gate = new();

    /// <inheritdoc />
    public Task<SecureTextDeviceIdentity?> LoadAsync(string key, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentException.ThrowIfNullOrWhiteSpace(key);

        lock (_gate)
        {
            return Task.FromResult(
                _identities.TryGetValue(key, out var identity)
                    ? Clone(identity)
                    : null);
        }
    }

    /// <inheritdoc />
    public Task StoreAsync(string key, SecureTextDeviceIdentity identity, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        ArgumentNullException.ThrowIfNull(identity);

        lock (_gate)
            _identities[key] = Clone(identity);

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task RemoveAsync(string key, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentException.ThrowIfNullOrWhiteSpace(key);

        lock (_gate)
            _identities.Remove(key);

        return Task.CompletedTask;
    }

    private static SecureTextDeviceIdentity Clone(SecureTextDeviceIdentity identity) =>
        SecureTextDeviceIdentity.Import(
            identity.DeviceId,
            identity.ExportSigningPrivateKey(),
            identity.ExportAgreementPrivateKey());
}
