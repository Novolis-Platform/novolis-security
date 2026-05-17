using FluentAssertions;
using Novolis.Security.Encryption;
using Microsoft.Extensions.Options;

namespace Novolis.Security.Tests;

public class StringEncryptorTests
{
    [Test]
    public void EncryptionDecryptionTest()
    {
        var options = Options.Create(new StringEncryptorOptions());
        var stringEncryptor = new StringEncryptor(options);
        var original = "Hello, World!";
        var key = Guid.NewGuid();
        TestContext.Current?.OutputWriter.WriteLine($"Original string: {original}");
        TestContext.Current?.OutputWriter.WriteLine($"Key: {key}");

        var encrypted = stringEncryptor.Encrypt(original, key);
        var decrypted = stringEncryptor.Decrypt(encrypted, key);

        decrypted.Should().Be(original);
    }
}
