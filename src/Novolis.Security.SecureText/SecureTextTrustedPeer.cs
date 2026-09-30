using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Novolis.Security.SecureText;

/// <summary>Previously confirmed public identity for a remote device.</summary>
public sealed class SecureTextTrustedPeer
{
    private readonly byte[] _fingerprint;

    /// <summary>Creates a pinned peer record from a public bundle verified by the user.</summary>
    public SecureTextTrustedPeer(SecureTextPublicBundle bundle)
    {
        ArgumentNullException.ThrowIfNull(bundle);
        if (!bundle.Verify())
            throw new CryptographicException("The public bundle signature or validity window is invalid.");

        DeviceId = bundle.DeviceId;
        _fingerprint = Convert.FromHexString(bundle.GetFingerprint());
    }

    private SecureTextTrustedPeer(Guid deviceId, byte[] fingerprint)
    {
        if (deviceId == Guid.Empty)
            throw new ArgumentException("A device id is required.", nameof(deviceId));
        if (fingerprint.Length != SHA256.HashSizeInBytes)
            throw new ArgumentException("The peer fingerprint length is invalid.", nameof(fingerprint));

        DeviceId = deviceId;
        _fingerprint = fingerprint;
    }

    /// <summary>Restores a previously confirmed peer fingerprint from protected host storage.</summary>
    public static SecureTextTrustedPeer FromFingerprint(Guid deviceId, string fingerprint)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fingerprint);
        try
        {
            return new SecureTextTrustedPeer(deviceId, Convert.FromHexString(fingerprint));
        }
        catch (FormatException exception)
        {
            throw new ArgumentException("The peer fingerprint is not valid hexadecimal.", nameof(fingerprint), exception);
        }
    }

    /// <summary>Expected remote device id.</summary>
    public Guid DeviceId { get; }

    /// <summary>Returns the pinned bundle fingerprint for display and auditing.</summary>
    public string GetFingerprint() => Convert.ToHexString(_fingerprint);

    /// <summary>Verifies that a presented public bundle is still the pinned peer.</summary>
    public void VerifyBundle(SecureTextPublicBundle bundle, DateTimeOffset? nowUtc = null)
    {
        ArgumentNullException.ThrowIfNull(bundle);
        if (bundle.DeviceId != DeviceId)
            throw new CryptographicException("The presented bundle belongs to a different device.");
        if (!bundle.Verify(nowUtc))
            throw new CryptographicException("The presented bundle signature or validity window is invalid.");

        var actual = Convert.FromHexString(bundle.GetFingerprint());
        if (!CryptographicOperations.FixedTimeEquals(_fingerprint, actual))
            throw new CryptographicException("The peer public key fingerprint changed and must be confirmed again.");
    }
}
