using Novolis.Security.Secrets;
using TUnit.Core;

namespace Novolis.Security.Tests;

public class SecretBuilderTests
{
    [Test]
    public async Task GenerateFromSettings_ShouldCreateCharsetSecret()
    {
        var options = new SecretGeneratorOptions();
        var secret = SecretBuilder.GenerateFromSettings(options);

        await Assert.That(secret).IsNotNullOrEmpty();
        await Assert.That(secret.Length).IsEqualTo(options.Length);
        TestContext.Current?.OutputWriter.WriteLine($"Generated secret: {secret}");
    }
}
