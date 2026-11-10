using Novolis.Security.Authentication.Enrollment;

namespace Novolis.Security.Unit;

public sealed class EnrollmentTokenMintTests
{
    [Test]
    public async Task CreateLink_UsesOriginPathAndEscapedToken()
    {
        var mint = new EnrollmentTokenMint(new EnrollmentTokenOptions
        {
            Pepper = "unit-test-pepper",
            LinkPath = "invite",
            TokenQueryName = "token",
        });

        var reference = mint.CreateReference();
        var link = mint.CreateLink("https://app.example/", reference);
        var token = mint.CreateToken(reference);

        await Assert.That(link).StartsWith("https://app.example/invite?token=");
        await Assert.That(link).Contains(Uri.EscapeDataString(token));
        await Assert.That(mint.HashToken(token)).IsNotEmpty();
        await Assert.That(mint.CreateTemporaryPassword(reference)).StartsWith("En!9a");
    }

    [Test]
    public async Task ResolvePepper_RequiresConfiguredPepperOutsideDevelopment()
    {
        var mint = new EnrollmentTokenMint(new EnrollmentTokenOptions
        {
            AllowDevelopmentPepper = false,
        });

        await Assert.That(() => mint.CreateToken("ref"))
            .Throws<InvalidOperationException>();
    }
}
