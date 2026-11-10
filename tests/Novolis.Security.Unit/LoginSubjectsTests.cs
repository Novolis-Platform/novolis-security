using Novolis.Security.Authentication.Subjects;

namespace Novolis.Security.Unit;

public sealed class LoginSubjectsTests
{
    [Test]
    public async Task TryCreate_Email_Normalizes()
    {
        var ok = LoginSubjects.TryCreate(
            LoginSubjectKind.Email,
            " Ada@Example.COM ",
            issuer: null,
            out var subject,
            out var error);

        await Assert.That(ok).IsTrue();
        await Assert.That(error).IsNull();
        await Assert.That(subject!.Value).IsEqualTo("ada@example.com");
        await Assert.That(subject.Kind).IsEqualTo(LoginSubjectKind.Email);
    }

    [Test]
    public async Task TryCreate_OpenIdConnect_FormatsStableKey()
    {
        var ok = LoginSubjects.TryCreate(
            LoginSubjectKind.OpenIdConnect,
            "subject-1",
            "https://login.microsoftonline.com/common/v2.0/",
            out var subject,
            out _);

        await Assert.That(ok).IsTrue();
        await Assert.That(subject!.Value)
            .IsEqualTo("oidc:https://login.microsoftonline.com/common/v2.0:subject-1");
        await Assert.That(LoginSubjects.Parse(subject.Value).IsOpenIdConnect).IsTrue();
    }

    [Test]
    public async Task IsEmail_RejectsOidcKeys()
    {
        await Assert.That(LoginSubjects.IsEmail("oidc:https://issuer:sub")).IsFalse();
        await Assert.That(LoginSubjects.IsEmail("ada@example.com")).IsTrue();
    }
}
