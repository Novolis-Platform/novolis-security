using Microsoft.Extensions.DependencyInjection;
using Novolis.Security.Authentication;
using TUnit.Core;

namespace Novolis.Security.Tests;

public class AuthenticationIsolationTests
{
    [Test]
    public async Task CredentialRecord_HasNoIdentityOrLoginFields()
    {
        var names = typeof(CredentialRecord).GetProperties().Select(p => p.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        string[] forbidden =
        [
            "Email", "Username", "UserName", "Phone", "DisplayName", "IdentityId", "TenantId", "GroupId", "RoleId",
        ];
        foreach (var name in forbidden)
            await Assert.That(names.Contains(name)).IsFalse();
    }

    [Test]
    public async Task SignIn_UnknownAndWrongPassword_LookTheSame()
    {
        await using var provider = OAuthTestHost.CreateProvider();
        var authentication = provider.GetRequiredService<IAuthenticationService>();
        await authentication.RegisterAsync("frank", "correct horse", createSession: false);
        var missing = await authentication.SignInAsync("missing", "correct horse", createSession: false);
        var wrong = await authentication.SignInAsync("frank", "nope", createSession: false);
        await Assert.That(missing.Succeeded).IsFalse();
        await Assert.That(wrong.Succeeded).IsFalse();
        await Assert.That(missing.Error).IsEqualTo(wrong.Error);
    }

    [Test]
    public async Task Register_CreatesIsolatedCredential_AndSession()
    {
        await using var provider = OAuthTestHost.CreateProvider();
        var authentication = provider.GetRequiredService<IAuthenticationService>();
        var identities = provider.GetRequiredService<IIdentityStore>();
        var credentials = provider.GetRequiredService<ICredentialStore>();
        var result = await authentication.RegisterAsync("frank", "correct horse");
        await Assert.That(result.Succeeded).IsTrue();
        var identity = await identities.TryGetAsync(result.IdentityId!.Value);
        var credential = await credentials.TryGetAsync(identity!.CredentialReference);
        await Assert.That(credential).IsNotNull();
        await Assert.That(credential!.GetType().GetProperty("IdentityId")).IsNull();
        await Assert.That(await authentication.GetAuthenticatedIdentityAsync(result.SessionId!))
            .IsEqualTo(result.IdentityId);
    }
}
