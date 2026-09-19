using System.Security.Cryptography;

namespace Novolis.Security.SecureText;

/// <summary>Long-lived private identity material for one secure-text device.</summary>
public sealed class SecureTextDeviceIdentity
{
    private readonly byte[] _agreementPrivateKey;
    private readonly byte[] _signingPrivateKey;

    private SecureTextDeviceIdentity(Guid deviceId, byte[] signingPrivateKey, byte[] agreementPrivateKey)
    {
        if (deviceId == Guid.Empty)
            throw new ArgumentException("A device id is required.", nameof(deviceId));

        DeviceId = deviceId;
        _signingPrivateKey = signingPrivateKey;
        _agreementPrivateKey = agreementPrivateKey;
    }

    /// <summary>Stable identifier for this device identity.</summary>
    public Guid DeviceId { get; }

    /// <summary>Creates a new P-256 signing and key-agreement identity.</summary>
    public static SecureTextDeviceIdentity Create(Guid? deviceId = null)
    {
        using var signing = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var agreement = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);

        return new SecureTextDeviceIdentity(
            deviceId ?? Guid.CreateVersion7(),
            signing.ExportPkcs8PrivateKey(),
            agreement.ExportPkcs8PrivateKey());
    }

    /// <summary>Imports validated PKCS#8 private key material from a secure store.</summary>
    public static SecureTextDeviceIdentity Import(
        Guid deviceId,
        ReadOnlySpan<byte> signingPrivateKey,
        ReadOnlySpan<byte> agreementPrivateKey)
    {
        if (signingPrivateKey.IsEmpty)
            throw new ArgumentException("Signing key material is required.", nameof(signingPrivateKey));
        if (agreementPrivateKey.IsEmpty)
            throw new ArgumentException("Agreement key material is required.", nameof(agreementPrivateKey));

        using var signing = ECDsa.Create();
        signing.ImportPkcs8PrivateKey(signingPrivateKey, out var signingRead);
        if (signingRead != signingPrivateKey.Length || signing.KeySize != 256)
            throw new CryptographicException("The signing key must be a P-256 PKCS#8 key.");

        using var agreement = ECDiffieHellman.Create();
        agreement.ImportPkcs8PrivateKey(agreementPrivateKey, out var agreementRead);
        if (agreementRead != agreementPrivateKey.Length || agreement.KeySize != 256)
            throw new CryptographicException("The agreement key must be a P-256 PKCS#8 key.");

        return new SecureTextDeviceIdentity(
            deviceId,
            signingPrivateKey.ToArray(),
            agreementPrivateKey.ToArray());
    }

    /// <summary>Exports the signing private key for a platform-backed secure store.</summary>
    public byte[] ExportSigningPrivateKey() => _signingPrivateKey.ToArray();

    /// <summary>Exports the agreement private key for a platform-backed secure store.</summary>
    public byte[] ExportAgreementPrivateKey() => _agreementPrivateKey.ToArray();

    internal ECDsa CreateSigningAlgorithm()
    {
        var signing = ECDsa.Create();
        signing.ImportPkcs8PrivateKey(_signingPrivateKey, out _);
        return signing;
    }

    internal ECDiffieHellman CreateAgreementAlgorithm()
    {
        var agreement = ECDiffieHellman.Create();
        agreement.ImportPkcs8PrivateKey(_agreementPrivateKey, out _);
        return agreement;
    }
}

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
