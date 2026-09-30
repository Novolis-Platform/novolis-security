using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Novolis.Security.SecureText;

/// <summary>Derives pairwise AES-256 keys from trusted P-256 device bundles.</summary>
public static class SecureTextKeyAgreement
{
    private static readonly byte[] DerivationLabel = "Novolis.SecureText.v1.session"u8.ToArray();

    /// <summary>
    /// Derives a conversation key for a particular key epoch. Both endpoints must pass
    /// the same conversation id and the two signed public bundles.
    /// </summary>
    public static byte[] DeriveSessionKey(
        SecureTextDeviceIdentity localIdentity,
        SecureTextPublicBundle localBundle,
        SecureTextPublicBundle peerBundle,
        Guid conversationId,
        int keyEpoch)
    {
        ArgumentNullException.ThrowIfNull(localIdentity);
        ArgumentNullException.ThrowIfNull(localBundle);
        ArgumentNullException.ThrowIfNull(peerBundle);
        if (conversationId == Guid.Empty)
            throw new ArgumentException("A conversation id is required.", nameof(conversationId));
        if (keyEpoch < 1)
            throw new ArgumentOutOfRangeException(nameof(keyEpoch), "The key epoch must be positive.");
        if (localIdentity.DeviceId != localBundle.DeviceId)
            throw new CryptographicException("The local bundle does not belong to the local identity.");
        if (!localBundle.Verify() || !peerBundle.Verify())
            throw new CryptographicException("A public bundle signature or validity window is invalid.");

        using var localAgreement = localIdentity.CreateAgreementAlgorithm();
        using var peerAgreement = ECDiffieHellman.Create();
        var peerPublicKey = peerBundle.ExportAgreementPublicKey();
        peerAgreement.ImportSubjectPublicKeyInfo(peerPublicKey, out var peerRead);
        if (peerRead != peerPublicKey.Length || peerAgreement.KeySize != 256)
            throw new CryptographicException("The peer agreement key must be P-256 SubjectPublicKeyInfo.");

        var secret = localAgreement.DeriveRawSecretAgreement(peerAgreement.PublicKey);
        var context = CreateContext(conversationId, keyEpoch, localBundle, peerBundle);
        var salt = SHA256.HashData(context);
        try
        {
            return HKDF.DeriveKey(
                HashAlgorithmName.SHA256,
                secret,
                SecureTextProtocol.SessionKeyBytes,
                salt,
                DerivationLabel);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
            CryptographicOperations.ZeroMemory(salt);
        }
    }

    private static byte[] CreateContext(
        Guid conversationId,
        int keyEpoch,
        SecureTextPublicBundle first,
        SecureTextPublicBundle second)
    {
        var firstFingerprint = Convert.FromHexString(first.GetFingerprint());
        var secondFingerprint = Convert.FromHexString(second.GetFingerprint());
        if (firstFingerprint.AsSpan().SequenceCompareTo(secondFingerprint) > 0)
            (firstFingerprint, secondFingerprint) = (secondFingerprint, firstFingerprint);

        using var stream = new MemoryStream();
        stream.Write("Novolis.SecureText.v1.context"u8);
        stream.Write(conversationId.ToByteArray(bigEndian: true));
        Span<byte> epoch = stackalloc byte[sizeof(int)];
        BinaryPrimitives.WriteInt32BigEndian(epoch, keyEpoch);
        stream.Write(epoch);
        stream.Write(firstFingerprint);
        stream.Write(secondFingerprint);
        return stream.ToArray();
    }
}
