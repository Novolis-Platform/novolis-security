using System.Reflection;
using Novolis.Security.Authentication;
using Novolis.Security.Authorization;
using Novolis.Security.OAuth;
using TUnit.Core;

namespace Novolis.Security.Tests;

public class SecurityArchitectureTests
{
    [Test]
    public async Task OAuthAssembly_DoesNotReferenceAuthorization()
    {
        var names = typeof(OAuthTokenService).Assembly.GetReferencedAssemblies().Select(a => a.Name);
        await Assert.That(names.Contains("Novolis.Security.Authorization")).IsFalse();
        await Assert.That(names.Contains("Novolis.Security.Authorization.Abstractions")).IsFalse();
    }

    [Test]
    public async Task AuthorizationAssembly_DoesNotReferenceOAuth()
    {
        var names = typeof(AuthorizationService).Assembly.GetReferencedAssemblies().Select(a => a.Name);
        await Assert.That(names.Contains("Novolis.Security.OAuth")).IsFalse();
        await Assert.That(names.Contains("Novolis.Security.OAuth.Abstractions")).IsFalse();
    }

    [Test]
    public async Task CredentialStore_HasNoIdentityLookup()
    {
        var methods = typeof(ICredentialStore).GetMethods().Select(m => m.Name);
        await Assert.That(methods.Any(m =>
            m.Contains("Email", StringComparison.OrdinalIgnoreCase)
            || m.Contains("User", StringComparison.OrdinalIgnoreCase)
            || m.Contains("Identity", StringComparison.OrdinalIgnoreCase))).IsFalse();
    }

    [Test]
    public async Task AuthenticationAssembly_DoesNotReferenceBreachChecking()
    {
        var names = typeof(AuthenticationService).Assembly.GetReferencedAssemblies().Select(a => a.Name);
        await Assert.That(names.Contains("Novolis.Security.HaveIBeenPwned")).IsFalse();
    }

    [Test]
    public async Task NoPublishedIdpPackageNamesRemainInSecurityAssemblies()
    {
        var assemblies = new[]
        {
            typeof(IdentityId).Assembly,
            typeof(OAuthTokenService).Assembly,
            typeof(AuthorizationService).Assembly,
        };
        foreach (var assembly in assemblies)
            await Assert.That(assembly.GetName().Name!.Contains("Idp", StringComparison.Ordinal)).IsFalse();
    }
}
