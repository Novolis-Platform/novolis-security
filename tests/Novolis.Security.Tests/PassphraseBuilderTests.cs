using FluentAssertions;
using Novolis.Security.Secrets;

namespace Novolis.Security.Tests;

public class PassphraseBuilderTests
{
    [Test]
    public void Build_WithDefaultWordLists_ShouldCreatePassphrase()
    {
        var passphrase = new PassphraseBuilder(4)
            .IncludeNouns()
            .IncludeAdjectives()
            .IncludeVerbs()
            .Shuffle()
            .Build();

        passphrase.Should().NotBeNullOrWhiteSpace();
        passphrase.Split(' ').Should().HaveCount(4);
    }

    [Test]
    public void GenerateWordPassphrase_ShouldMatchBuilderDefaults()
    {
        var generator = new SecretGenerator();
        var passphrase = generator.GenerateWordPassphrase();

        passphrase.Should().NotBeNullOrWhiteSpace();
        passphrase.Split(' ').Should().HaveCount(4);
    }
}
