using Novolis.Security.Secrets;
using TUnit.Core;

namespace Novolis.Security.Tests;

public class SecretGeneratorTests
{
    [Test]
    public async Task GenerateCharsetSecret_ShouldHonorLength()
    {
        var generator = new SecretGenerator();
        var secret = generator.GenerateCharsetSecret(new SecretGeneratorOptions { Length = 24 });

        await Assert.That(secret.Length).IsEqualTo(24);
    }
}
