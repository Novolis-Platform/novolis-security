using FluentAssertions;
using Novolis.Security.Secrets;

namespace Novolis.Security.Tests;

public class SecretBuilderTests
{
    [Test]
    public void GenerateFromSettings_ShouldCreateCharsetSecret()
    {
        var options = new SecretGeneratorOptions();
        var secret = SecretBuilder.GenerateFromSettings(options);

        secret.Should().NotBeNullOrEmpty();
        secret.Length.Should().Be(options.Length);
        TestContext.Current?.OutputWriter.WriteLine($"Generated secret: {secret}");
    }
}
