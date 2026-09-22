using System.Security.Cryptography;
using Novolis.Security.Encryption;
using Microsoft.Extensions.Options;
using TUnit.Core;

namespace Novolis.Security.Tests;

public class StringEncryptorTests
{
    [Test]
    public async Task EncryptionDecryptionTest()
    {
        var stringEncryptor = new StringEncryptor(Options.Create(new StringEncryptorOptions()));
        var original = "Hello, World!";
        var key = StringEncryptor.CreateKey();

        var encrypted = stringEncryptor.Encrypt(original, key);
        var decrypted = stringEncryptor.Decrypt(encrypted, key);

        await Assert.That(decrypted).IsEqualTo(original);
    }

    [Test]
    public async Task EncryptEmptyString_RoundTrips()
    {
        var stringEncryptor = new StringEncryptor(Options.Create(new StringEncryptorOptions()));
        var key = StringEncryptor.CreateKey();

        var encrypted = stringEncryptor.Encrypt(string.Empty, key);
        var decrypted = stringEncryptor.Decrypt(encrypted, key);

        await Assert.That(decrypted).IsEqualTo(string.Empty);
    }

    [Test]
    public async Task Decrypt_WrongKey_Throws()
    {
        var stringEncryptor = new StringEncryptor(Options.Create(new StringEncryptorOptions()));
        var encrypted = stringEncryptor.Encrypt("secret", StringEncryptor.CreateKey());

        await Assert.That(() => stringEncryptor.Decrypt(encrypted, StringEncryptor.CreateKey()))
            .Throws<CryptographicException>();
    }

    [Test]
    public async Task Decrypt_TamperedCiphertext_Throws()
    {
        var stringEncryptor = new StringEncryptor(Options.Create(new StringEncryptorOptions()));
        var key = StringEncryptor.CreateKey();
        var packed = Convert.FromBase64String(stringEncryptor.Encrypt("secret", key));
        packed[^1] ^= 0xFF;
        await Assert.That(() => stringEncryptor.Decrypt(Convert.ToBase64String(packed), key))
            .Throws<CryptographicException>();
    }
}
