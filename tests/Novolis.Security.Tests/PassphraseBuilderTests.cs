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
}
