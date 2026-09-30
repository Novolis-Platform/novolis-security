using System.Security.Cryptography;

namespace Novolis.Security.SecureText;

/// <summary>Host-provided protected storage for a secure-text device identity.</summary>
public interface ISecureTextKeyStore
{
    /// <summary>Loads an identity, or <see langword="null"/> when the key has not been enrolled.</summary>
    Task<SecureTextDeviceIdentity?> LoadAsync(string key, CancellationToken cancellationToken = default);

    /// <summary>Stores an identity using protected platform storage.</summary>
    Task StoreAsync(string key, SecureTextDeviceIdentity identity, CancellationToken cancellationToken = default);

    /// <summary>Removes a stored identity.</summary>
    Task RemoveAsync(string key, CancellationToken cancellationToken = default);
}
