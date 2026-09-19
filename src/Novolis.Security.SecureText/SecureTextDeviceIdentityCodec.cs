using System.Buffers.Binary;

namespace Novolis.Security.SecureText;

/// <summary>Canonical binary codec for storing a device identity in a protected host store.</summary>
public static class SecureTextDeviceIdentityCodec
{
    private const int FormatVersion = 1;
    private const int MaximumPrivateKeyBytes = 4096;

    /// <summary>Serializes private identity material for storage by an <see cref="ISecureTextKeyStore"/> implementation.</summary>
    public static byte[] Serialize(SecureTextDeviceIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);
        var signing = identity.ExportSigningPrivateKey();
        var agreement = identity.ExportAgreementPrivateKey();

        using var stream = new MemoryStream();
        WriteInt32(stream, FormatVersion);
        stream.Write(identity.DeviceId.ToByteArray(bigEndian: true));
        WriteBlob(stream, signing);
        WriteBlob(stream, agreement);
        return stream.ToArray();
    }

    /// <summary>Deserializes and validates a protected identity payload.</summary>
    public static SecureTextDeviceIdentity Deserialize(ReadOnlySpan<byte> payload)
    {
        using var stream = new MemoryStream(payload.ToArray(), writable: false);
        var version = ReadInt32(stream);
        if (version != FormatVersion)
            throw new NotSupportedException($"Secure-text identity format {version} is not supported.");

        var deviceBytes = ReadExact(stream, 16);
        var deviceId = new Guid(deviceBytes, bigEndian: true);
        var signing = ReadBlob(stream);
        var agreement = ReadBlob(stream);
        if (stream.Position != stream.Length)
            throw new InvalidDataException("The protected identity payload has trailing data.");

        return SecureTextDeviceIdentity.Import(deviceId, signing, agreement);
    }

    private static byte[] ReadBlob(Stream stream)
    {
        var length = ReadInt32(stream);
        if (length is < 1 or > MaximumPrivateKeyBytes)
            throw new InvalidDataException("The protected identity key length is invalid.");

        return ReadExact(stream, length);
    }

    private static byte[] ReadExact(Stream stream, int length)
    {
        var bytes = new byte[length];
        var offset = 0;
        while (offset < bytes.Length)
        {
            var read = stream.Read(bytes, offset, bytes.Length - offset);
            if (read == 0)
                throw new EndOfStreamException("The protected identity payload is truncated.");
            offset += read;
        }

        return bytes;
    }

    private static int ReadInt32(Stream stream)
    {
        var bytes = ReadExact(stream, sizeof(int));
        return BinaryPrimitives.ReadInt32BigEndian(bytes);
    }

    private static void WriteBlob(Stream stream, ReadOnlySpan<byte> value)
    {
        if (value.Length is < 1 or > MaximumPrivateKeyBytes)
            throw new ArgumentOutOfRangeException(nameof(value), "The private key length is invalid.");
        WriteInt32(stream, value.Length);
        stream.Write(value);
    }

    private static void WriteInt32(Stream stream, int value)
    {
        Span<byte> bytes = stackalloc byte[sizeof(int)];
        BinaryPrimitives.WriteInt32BigEndian(bytes, value);
        stream.Write(bytes);
    }
}
