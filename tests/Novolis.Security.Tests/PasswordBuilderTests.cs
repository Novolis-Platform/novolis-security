using FluentAssertions;
using Novolis.Security.Cryptography;

namespace Novolis.Security.Tests;

public class PasswordBuilderTests
{
    [Test]
    public void GenerateFromSettings_ShouldCreatePassword()
    {
        PasswordGeneratorOptions options = new();
        var password = PasswordBuilder.GenerateFromSettings(options);

        password.Should().NotBeNullOrEmpty();
        password.Length.Should().Be(options.Length);
        TestContext.Current?.OutputWriter.WriteLine($"Generated Password: {password}");
    }
}
