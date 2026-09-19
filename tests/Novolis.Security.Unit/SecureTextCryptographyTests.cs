using System.Security.Cryptography;
using System.Text;
using Novolis.Security.SecureText;

namespace Novolis.Security.Tests;

public sealed class SecureTextCryptographyTests
{
    [Test]
    public async Task Trusted_pair_derives_the_same_session_key()
    {
        var alice = SecureTextDeviceIdentity.Create();
        var bob = SecureTextDeviceIdentity.Create();
        var aliceBundle = SecureTextPublicBundle.Create(alice);
        var bobBundle = SecureTextPublicBundle.Create(bob);
        var conversationId = Guid.CreateVersion7();

        var aliceKey = SecureTextKeyAgreement.DeriveSessionKey(alice, aliceBundle, bobBundle, conversationId, 1);
        var bobKey = SecureTextKeyAgreement.DeriveSessionKey(bob, bobBundle, aliceBundle, conversationId, 1);

        try
        {
            await Assert.That(aliceBundle.Verify()).IsTrue();
            await Assert.That(bobBundle.Verify()).IsTrue();
            await Assert.That(aliceKey).IsEquivalentTo(bobKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(aliceKey);
            CryptographicOperations.ZeroMemory(bobKey);
        }
    }

    [Test]
    public async Task Aead_rejects_a_changed_authenticated_header()
    {
        var key = RandomNumberGenerator.GetBytes(SecureTextProtocol.SessionKeyBytes);
        var plaintext = Encoding.UTF8.GetBytes("endpoint-only text");
        var associatedData = Encoding.UTF8.GetBytes("header-a");
        var changedAssociatedData = Encoding.UTF8.GetBytes("header-b");

        try
        {
            var ciphertext = SecureTextAead.Seal(key, plaintext, associatedData);
            await Assert.That(() => SecureTextAead.Open(key, ciphertext, changedAssociatedData))
                .Throws<CryptographicException>();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    [Test]
    public async Task Changed_bundle_signature_is_not_trusted()
    {
        var identity = SecureTextDeviceIdentity.Create();
        var bundle = SecureTextPublicBundle.Create(identity);
        var changedSignature = bundle.ExportSignature();
        changedSignature[0] ^= 0x01;
        var altered = new SecureTextPublicBundle(
            bundle.ProtocolVersion,
            bundle.DeviceId,
            bundle.ExportSigningPublicKey(),
            bundle.ExportAgreementPublicKey(),
            bundle.IssuedAtUtc,
            bundle.ExpiresAtUtc,
            changedSignature);

        await Assert.That(altered.Verify()).IsFalse();
        await Assert.That(() => new SecureTextTrustedPeer(altered)).Throws<CryptographicException>();
    }

    [Test]
    public async Task Protected_identity_codec_round_trips()
    {
        var identity = SecureTextDeviceIdentity.Create();
        var payload = SecureTextDeviceIdentityCodec.Serialize(identity);

        var restored = SecureTextDeviceIdentityCodec.Deserialize(payload);

        await Assert.That(restored.DeviceId).IsEqualTo(identity.DeviceId);
        await Assert.That(restored.ExportSigningPrivateKey()).IsEquivalentTo(identity.ExportSigningPrivateKey());
        await Assert.That(restored.ExportAgreementPrivateKey()).IsEquivalentTo(identity.ExportAgreementPrivateKey());
    }
}
