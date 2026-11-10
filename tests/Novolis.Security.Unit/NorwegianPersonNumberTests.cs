using Novolis.Security.Authentication.Subjects;

namespace Novolis.Security.Unit;

public sealed class NorwegianPersonNumberTests
{
    /// <summary>Structurally valid synthetic number (not a real person).</summary>
    private const string ValidExample = "01017000027";

    [Test]
    public async Task TryNormalize_AcceptsValidCheckDigits()
    {
        await Assert.That(NorwegianPersonNumber.TryNormalize("010 170 00027", out var digits)).IsTrue();
        await Assert.That(digits).IsEqualTo(ValidExample);
    }

    [Test]
    public async Task SecuredMint_OwnerSeesOnlyObscuredMask()
    {
        var mint = new SecuredLoginMint(new SecuredLoginOptions { Pepper = "unit-test-pepper" });
        var ok = LoginSubjects.TryCreateSecuredAlphanumeric(
            ValidExample,
            mint,
            out var subject,
            out var ownerLogin,
            out _);

        await Assert.That(ok).IsTrue();
        await Assert.That(subject!.Value).StartsWith("sec:");
        await Assert.That(subject.Value).DoesNotContain(ValidExample);
        await Assert.That(ownerLogin).IsEqualTo(LoginDisplay.ObscuredLogin);
        await Assert.That(LoginDisplay.DescribeStored(subject.Value)).IsEqualTo("********");
    }
}
