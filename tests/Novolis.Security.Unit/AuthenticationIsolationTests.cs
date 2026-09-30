using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Novolis.Security.Authentication;
using Novolis.Security.PasswordHashing;
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

    [Test]
    public async Task Register_RejectsShortPassword()
    {
        await using var provider = OAuthTestHost.CreateProvider();
        var authentication = provider.GetRequiredService<IAuthenticationService>();
        var result = await authentication.RegisterAsync("short-user", "short");
        await Assert.That(result.Succeeded).IsFalse();
        await Assert.That(result.Error).IsEqualTo("password_too_short");
    }

    [Test]
    public async Task Register_RejectsBreachedPassword()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.Configure<PasswordHasherOptions>(OAuthTestHost.FastArgon);
        services.AddSingleton<IPasswordBreachChecker, RejectingPasswordBreachChecker>();
        services.AddNovolisAuthentication(o => o.IsDevelopment = true);
        await using var provider = services.BuildServiceProvider();
        var authentication = provider.GetRequiredService<IAuthenticationService>();
        var result = await authentication.RegisterAsync("breached-user", "correct horse battery staple");
        await Assert.That(result.Succeeded).IsFalse();
        await Assert.That(result.Error).IsEqualTo("password_breached");
    }

    [Test]
    public async Task SignIn_LocksCredential_AfterFailureBudget()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.Configure<PasswordHasherOptions>(OAuthTestHost.FastArgon);
        services.AddSingleton<IPasswordBreachChecker>(_ => AllowingPasswordBreachChecker.Instance);
        services.AddNovolisAuthentication(o =>
        {
            o.IsDevelopment = true;
            o.MaxSignInFailures = 3;
            o.SignInFailureWindow = TimeSpan.FromMinutes(15);
        });
        await using var provider = services.BuildServiceProvider();
        var authentication = provider.GetRequiredService<IAuthenticationService>();
        var credentials = provider.GetRequiredService<ICredentialStore>();
        var identities = provider.GetRequiredService<IIdentityStore>();
        await authentication.RegisterAsync("frank", "correct horse", createSession: false);

        for (var i = 0; i < 3; i++)
        {
            var failed = await authentication.SignInAsync("frank", "wrong password", createSession: false);
            await Assert.That(failed.Succeeded).IsFalse();
            await Assert.That(failed.Error).IsEqualTo("invalid_credentials");
        }

        var locked = await authentication.SignInAsync("frank", "correct horse", createSession: false);
        await Assert.That(locked.Succeeded).IsFalse();
        await Assert.That(locked.Error).IsEqualTo("invalid_credentials");
        var identity = await identities.FindByIdentifierAsync("frank");
        var credential = await credentials.TryGetAsync(identity!.CredentialReference);
        await Assert.That(credential!.Disabled).IsTrue();
    }

    [Test]
    public async Task SignIn_ProductMfa_RequiresProof_AndConsumesItOnce()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.Configure<PasswordHasherOptions>(OAuthTestHost.FastArgon);
        services.AddSingleton<IPasswordBreachChecker>(_ => AllowingPasswordBreachChecker.Instance);
        services.AddNovolisAuthentication(o => o.IsDevelopment = true);
        services.Replace(ServiceDescriptor.Singleton<IMfaProvider, ChallengeMfaProvider>());
        await using var provider = services.BuildServiceProvider();
        var authentication = provider.GetRequiredService<IAuthenticationService>();
        await authentication.RegisterAsync("frank", "correct horse", createSession: false);

        var missing = await authentication.SignInAsync("frank", "correct horse", createSession: false);
        await Assert.That(missing.Succeeded).IsFalse();
        await Assert.That(missing.Error).IsEqualTo("mfa_required");

        var ok = await authentication.SignInAsync("frank", "correct horse", createSession: false, mfaProof: "otp-1");
        await Assert.That(ok.Succeeded).IsTrue();

        var replay = await authentication.SignInAsync("frank", "correct horse", createSession: false, mfaProof: "otp-1");
        await Assert.That(replay.Succeeded).IsFalse();
        await Assert.That(replay.Error).IsEqualTo("mfa_invalid");
    }

    sealed class ChallengeMfaProvider : IMfaProvider
    {
        public async ValueTask<MfaDecision> CompleteAsync(
            MfaContext context,
            ICacheStore cache,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(context.Proof))
                return MfaDecision.Fail("mfa_required");
            if (!await cache.TryCreateAsync("auth:mfa:" + context.Proof, TimeSpan.FromMinutes(5), cancellationToken))
                return MfaDecision.Fail("mfa_invalid");
            await cache.SetTextAsync("auth:mfa:last:" + context.Credential, context.Proof, TimeSpan.FromMinutes(5), cancellationToken);
            return MfaDecision.Ok();
        }
    }

    sealed class RejectingPasswordBreachChecker : IPasswordBreachChecker
    {
        public ValueTask<bool> IsBreachedAsync(string password, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(true);
    }
}
