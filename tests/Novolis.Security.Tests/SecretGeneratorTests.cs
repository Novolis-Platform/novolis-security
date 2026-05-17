using FluentAssertions;
using Novolis.Security.Secrets;

namespace Novolis.Security.Tests;

public class SecretGeneratorTests
{
    [Test]
    public void GenerateCharsetSecret_ShouldHonorLength()
    {
        var generator = new SecretGenerator();
        var secret = generator.GenerateCharsetSecret(new SecretGeneratorOptions { Length = 24 });

        secret.Length.Should().Be(24);
    }
}
