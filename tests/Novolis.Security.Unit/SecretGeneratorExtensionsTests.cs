using Novolis.Security.Secrets;
using TUnit.Core;

namespace Novolis.Security.Tests;

public class SecretGeneratorExtensionsTests
{
    [Test]
    public async Task GenerateCharsetSecret_WithLengthOverload_ShouldHonorLength()
    {
        var generator = new SecretGenerator();
        var secret = generator.GenerateCharsetSecret(12);

        await Assert.That(secret.Length).IsEqualTo(12);
    }

    [Test]
    public async Task GenerateCharsetSecret_WithCharacterClassFlags_ShouldIncludeRequestedClasses()
    {
        var generator = new SecretGenerator();
        var secret = generator.GenerateCharsetSecret(
            length: 32,
            includeUppercase: true,
            includeLowercase: true,
            includeDigits: true,
            includeSpecial: true,
            includeHomoglyphs: true,
            includeWhitespace: true);

        await Assert.That(secret).IsNotNullOrEmpty();
        await Assert.That(secret.Length).IsEqualTo(32);
    }

    [Test]
    public async Task GenerateWordPassphrase_WithWordCountOverload_ShouldMatchWordCount()
    {
        var generator = new SecretGenerator();
        var passphrase = generator.GenerateWordPassphrase(3);

        await Assert.That(passphrase.Split(' ').Length).IsEqualTo(3);
    }
}
