using Novolis.Security.Secrets;
using TUnit.Core;

namespace Novolis.Security.Tests;

public class PassphraseBuilderTests
{
    [Test]
    public async Task Build_WithDefaultWordLists_ShouldCreatePassphrase()
    {
        var passphrase = new PassphraseBuilder(4)
            .IncludeNouns()
            .IncludeAdjectives()
            .IncludeVerbs()
            .Shuffle()
            .Build();

        await Assert.That(passphrase).IsNotNullOrWhiteSpace();
        await Assert.That(passphrase.Split(' ').Length).IsEqualTo(4);
    }

    [Test]
    public async Task GenerateWordPassphrase_ShouldMatchBuilderDefaults()
    {
        var generator = new SecretGenerator();
        var passphrase = generator.GenerateWordPassphrase();

        await Assert.That(passphrase).IsNotNullOrWhiteSpace();
        await Assert.That(passphrase.Split(' ').Length).IsEqualTo(4);
    }

    [Test]
    public async Task Build_WithAllWordLists_ShouldCreatePassphrase()
    {
        var passphrase = new PassphraseBuilder(5)
            .IncludeNouns()
            .IncludeAdjectives()
            .IncludeVerbs()
            .IncludeAdverbs()
            .IncludeCountries()
            .IncludeCultures()
            .IncludeColorNames()
            .Shuffle()
            .Build();

        await Assert.That(passphrase).IsNotNullOrWhiteSpace();
        await Assert.That(passphrase.Split(' ').Length).IsEqualTo(5);
    }

    [Test]
    public async Task Build_WithoutWordLists_ShouldThrow()
    {
        var builder = new PassphraseBuilder(4);

        await Assert.That(() => builder.Build()).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task GenerateWordPassphrase_WithAllOptionsEnabled_ShouldCreatePassphrase()
    {
        var generator = new SecretGenerator();
        var passphrase = generator.GenerateWordPassphrase(new PassphraseOptions
        {
            WordCount = 6,
            IncludeNouns = true,
            IncludeAdjectives = true,
            IncludeVerbs = true,
            IncludeAdverbs = true,
            IncludeCountries = true,
            IncludeCultures = true,
            IncludeColorNames = true
        });

        await Assert.That(passphrase.Split(' ').Length).IsEqualTo(6);
    }
}
