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

    [Test]
    public async Task PreviousPeppers_KeepOutstandingInviteHashesResolvable()
    {
        var oldMint = new EnrollmentTokenMint(new EnrollmentTokenOptions
        {
            Pepper = "old-pepper-0123456789abcdef01234567",
        });
        var reference = oldMint.CreateReference();
        var token = oldMint.CreateToken(reference);
        var oldHash = oldMint.HashToken(token);
        var oldTemp = oldMint.CreateTemporaryPassword(reference);

        var rotated = new EnrollmentTokenMint(new EnrollmentTokenOptions
        {
            Pepper = "new-pepper-0123456789abcdef01234567",
            PreviousPeppers = ["old-pepper-0123456789abcdef01234567"],
        });

        await Assert.That(rotated.HashTokenCandidates(token)).Contains(oldHash);
        await Assert.That(rotated.TryMatchTokenHash(token, oldHash, out var pepper)).IsTrue();
        await Assert.That(rotated.CreateTemporaryPassword(reference, pepper)).IsEqualTo(oldTemp);
        await Assert.That(rotated.HashToken(token)).IsNotEqualTo(oldHash);
        await Assert.That(rotated.CreateLinkMatching("https://app.example", reference, oldHash))
            .Contains(Uri.EscapeDataString(token));
    }

    [Test]
    public async Task ValidateConfiguration_RejectsShortProductionPepper()
    {
        var mint = new EnrollmentTokenMint(new EnrollmentTokenOptions
        {
            Pepper = "too-short",
            AllowDevelopmentPepper = false,
        });

        await Assert.That(mint.ValidateConfiguration).Throws<InvalidOperationException>();
    }
}
