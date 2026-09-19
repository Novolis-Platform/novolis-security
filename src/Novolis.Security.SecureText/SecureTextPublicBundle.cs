using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Novolis.Security.SecureText;

/// <summary>Constants shared by the secure-text v1 cryptographic protocol.</summary>
public static class SecureTextProtocol
{
    /// <summary>Current wire and key-derivation protocol version.</summary>
    public const int Version = 1;

    /// <summary>Maximum serialized public key length accepted by v1.</summary>
    public const int MaximumPublicKeyBytes = 1024;

    /// <summary>Length of a P-256 ECDSA signature in IEEE P1363 form.</summary>
    public const int SignatureBytes = 64;

    /// <summary>Length of AES-GCM nonces used by v1.</summary>
    public const int NonceBytes = 12;

    /// <summary>Length of AES-GCM authentication tags used by v1.</summary>
    public const int AuthenticationTagBytes = 16;

    /// <summary>Length of the AES-256 key used by v1.</summary>
    public const int SessionKeyBytes = 32;
}

/// <summary>
/// Signed public identity material for one device. A peer must still compare and pin the
/// fingerprint through a trusted out-of-band ceremony before accepting this bundle.
/// </summary>
public sealed class SecureTextPublicBundle
{
    private readonly byte[] _agreementPublicKey;
    private readonly byte[] _signature;
    private readonly byte[] _signingPublicKey;

    /// <summary>Creates a validated public bundle from wire material.</summary>
    public SecureTextPublicBundle(
        int protocolVersion,
        Guid deviceId,
        ReadOnlySpan<byte> signingPublicKey,
        ReadOnlySpan<byte> agreementPublicKey,
        DateTimeOffset issuedAtUtc,
        DateTimeOffset expiresAtUtc,
        ReadOnlySpan<byte> signature)
    {
        ProtocolVersion = protocolVersion;
        DeviceId = deviceId;
        _signingPublicKey = signingPublicKey.ToArray();
        _agreementPublicKey = agreementPublicKey.ToArray();
        IssuedAtUtc = issuedAtUtc.ToUniversalTime();
        ExpiresAtUtc = expiresAtUtc.ToUniversalTime();
        _signature = signature.ToArray();
        ValidateShape();
    }

    /// <summary>Protocol version that produced this bundle.</summary>
    public int ProtocolVersion { get; }

    /// <summary>Identity of the device that owns the bundle.</summary>
    public Guid DeviceId { get; }

    /// <summary>UTC time at which the bundle was signed.</summary>
    public DateTimeOffset IssuedAtUtc { get; }

    /// <summary>UTC time after which peers must not accept the bundle.</summary>
    public DateTimeOffset ExpiresAtUtc { get; }

    /// <summary>Returns a copy of the device ECDSA public key in SubjectPublicKeyInfo format.</summary>
    public byte[] ExportSigningPublicKey() => _signingPublicKey.ToArray();

    /// <summary>Returns a copy of the device ECDH public key in SubjectPublicKeyInfo format.</summary>
    public byte[] ExportAgreementPublicKey() => _agreementPublicKey.ToArray();

    /// <summary>Returns a copy of the fixed-width P-256 signature over this bundle.</summary>
    public byte[] ExportSignature() => _signature.ToArray();

    /// <summary>Creates a signed bundle for an enrolled device identity.</summary>
    public static SecureTextPublicBundle Create(
        SecureTextDeviceIdentity identity,
        DateTimeOffset? issuedAtUtc = null,
        TimeSpan? lifetime = null)
    {
        ArgumentNullException.ThrowIfNull(identity);
        var issued = (issuedAtUtc ?? DateTimeOffset.UtcNow).ToUniversalTime();
        var expires = issued.Add(lifetime ?? TimeSpan.FromDays(365));
        if (expires <= issued)
            throw new ArgumentOutOfRangeException(nameof(lifetime), "Bundle lifetime must be positive.");

        using var signing = identity.CreateSigningAlgorithm();
        using var agreement = identity.CreateAgreementAlgorithm();
        var unsigned = new SecureTextPublicBundle(
            SecureTextProtocol.Version,
            identity.DeviceId,
            signing.ExportSubjectPublicKeyInfo(),
            agreement.ExportSubjectPublicKeyInfo(),
            issued,
            expires,
            new byte[SecureTextProtocol.SignatureBytes]);
        var signature = signing.SignData(
            unsigned.GetUnsignedPayload(),
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        return new SecureTextPublicBundle(
            unsigned.ProtocolVersion,
            unsigned.DeviceId,
            unsigned._signingPublicKey,
            unsigned._agreementPublicKey,
            unsigned.IssuedAtUtc,
            unsigned.ExpiresAtUtc,
            signature);
    }

    /// <summary>Verifies the bundle's self-signature and expiration.</summary>
    public bool Verify(DateTimeOffset? nowUtc = null)
    {
        if ((nowUtc ?? DateTimeOffset.UtcNow).ToUniversalTime() > ExpiresAtUtc)
            return false;

        try
        {
            using var signing = ECDsa.Create();
            signing.ImportSubjectPublicKeyInfo(_signingPublicKey, out var read);
            return read == _signingPublicKey.Length
                   && signing.KeySize == 256
                   && signing.VerifyData(
                       GetUnsignedPayload(),
                       _signature,
                       HashAlgorithmName.SHA256,
                       DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    /// <summary>Returns the value users compare and pin when trusting a peer device.</summary>
    public string GetFingerprint()
    {
        var hash = SHA256.HashData(GetFingerprintPayload());
        return Convert.ToHexString(hash);
    }

    internal byte[] GetUnsignedPayload()
    {
        using var stream = new MemoryStream();
        WriteInt32(stream, ProtocolVersion);
        WriteGuid(stream, DeviceId);
        WriteBlob(stream, _signingPublicKey);
        WriteBlob(stream, _agreementPublicKey);
        WriteInt64(stream, IssuedAtUtc.ToUnixTimeMilliseconds());
        WriteInt64(stream, ExpiresAtUtc.ToUnixTimeMilliseconds());
        return stream.ToArray();
    }

    internal byte[] GetFingerprintPayload()
    {
        using var stream = new MemoryStream();
        WriteInt32(stream, ProtocolVersion);
        WriteGuid(stream, DeviceId);
        WriteBlob(stream, _signingPublicKey);
        WriteBlob(stream, _agreementPublicKey);
        return stream.ToArray();
    }

    private void ValidateShape()
    {
        if (ProtocolVersion != SecureTextProtocol.Version)
            throw new NotSupportedException($"Secure-text protocol version {ProtocolVersion} is not supported.");
        if (DeviceId == Guid.Empty)
            throw new ArgumentException("A device id is required.", nameof(DeviceId));
        if (IssuedAtUtc == default || ExpiresAtUtc <= IssuedAtUtc)
            throw new ArgumentException("The public bundle has an invalid validity window.");
        if (_signingPublicKey.Length is 0 or > SecureTextProtocol.MaximumPublicKeyBytes)
            throw new ArgumentException("The signing public key length is invalid.", nameof(_signingPublicKey));
        if (_agreementPublicKey.Length is 0 or > SecureTextProtocol.MaximumPublicKeyBytes)
            throw new ArgumentException("The agreement public key length is invalid.", nameof(_agreementPublicKey));
        if (_signature.Length != SecureTextProtocol.SignatureBytes)
            throw new ArgumentException("The public bundle signature length is invalid.", nameof(_signature));

        using var signing = ECDsa.Create();
        signing.ImportSubjectPublicKeyInfo(_signingPublicKey, out var signingRead);
        if (signingRead != _signingPublicKey.Length || signing.KeySize != 256)
            throw new CryptographicException("The signing public key must be P-256 SubjectPublicKeyInfo.");

        using var agreement = ECDiffieHellman.Create();
        agreement.ImportSubjectPublicKeyInfo(_agreementPublicKey, out var agreementRead);
        if (agreementRead != _agreementPublicKey.Length || agreement.KeySize != 256)
            throw new CryptographicException("The agreement public key must be P-256 SubjectPublicKeyInfo.");
    }

    private static void WriteBlob(Stream stream, ReadOnlySpan<byte> value)
    {
        WriteInt32(stream, value.Length);
        stream.Write(value);
    }

    private static void WriteGuid(Stream stream, Guid value) => stream.Write(value.ToByteArray(bigEndian: true));

    private static void WriteInt32(Stream stream, int value)
    {
        Span<byte> buffer = stackalloc byte[sizeof(int)];
        BinaryPrimitives.WriteInt32BigEndian(buffer, value);
        stream.Write(buffer);
    }

    private static void WriteInt64(Stream stream, long value)
    {
        Span<byte> buffer = stackalloc byte[sizeof(long)];
        BinaryPrimitives.WriteInt64BigEndian(buffer, value);
        stream.Write(buffer);
    }
}

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
