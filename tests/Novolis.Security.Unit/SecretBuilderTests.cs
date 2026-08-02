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

    [Test]
    public async Task GenerateFromSettings_WithAllCharacterClasses_ShouldCreateSecret()
    {
        var options = new SecretGeneratorOptions
        {
            Length = 20,
            IncludeUppercase = true,
            IncludeLowercase = true,
            IncludeDigits = true,
            IncludeSpecial = true,
            IncludeHomoglyphs = true,
            IncludeWhitespace = true
        };

        var secret = SecretBuilder.GenerateFromSettings(options);

        await Assert.That(secret.Length).IsEqualTo(20);
    }

    [Test]
    public async Task Build_WithIndividualCharacterSets_ShouldSampleIncludedCharacters()
    {
        var secret = new SecretBuilder(8)
            .IncludeSpecial()
            .IncludeHomoglyphs()
            .IncludeWhitespace()
            .Shuffle()
            .Build();

        await Assert.That(secret.Length).IsEqualTo(8);
    }

    [Test]
    public async Task Reset_ShouldClearCharacterPool()
    {
        var builder = new SecretBuilder(4)
            .IncludeUppercase()
            .IncludeLowercase();

        await Assert.That(builder.ToString()).IsNotEmpty();

        builder.Reset();
        await Assert.That(builder.ToString()).IsEmpty();
    }

    [Test]
    public async Task Build_WithoutCharacterSets_ShouldThrow()
    {
        var builder = new SecretBuilder(8);

        await Assert.That(() => builder.Build()).Throws<InvalidOperationException>();
    }
}
