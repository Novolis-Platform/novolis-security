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

    [Test]
    public async Task Defaults_UseLoggerEventSinks()
    {
        await using var provider = OAuthTestHost.CreateProvider();
        await Assert.That(provider.GetRequiredService<IAuthenticationEventSink>().GetType())
            .IsEqualTo(typeof(LoggerAuthenticationEventSink));
        await Assert.That(provider.GetRequiredService<Novolis.Security.OAuth.IEventStore>().GetType())
            .IsEqualTo(typeof(Novolis.Security.OAuth.LoggerEventStore));
    }

    [Test]
    public async Task Session_IdleTimeout_ExpiresWithoutAbsoluteLifetime()
    {
        var clock = new ManualTimeProvider();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<TimeProvider>(clock);
        services.Configure<PasswordHasherOptions>(OAuthTestHost.FastArgon);
        services.AddSingleton<IPasswordBreachChecker>(_ => AllowingPasswordBreachChecker.Instance);
        services.AddNovolisAuthentication(o =>
        {
            o.IsDevelopment = true;
            o.SessionIdleTimeout = TimeSpan.FromMinutes(5);
            o.SessionLifetime = TimeSpan.FromHours(8);
        });
        await using var provider = services.BuildServiceProvider();
        var authentication = provider.GetRequiredService<IAuthenticationService>();
        var result = await authentication.RegisterAsync("frank", "correct horse");
        await Assert.That(await authentication.GetAuthenticatedIdentityAsync(result.SessionId!))
            .IsEqualTo(result.IdentityId);

        clock.Advance(TimeSpan.FromMinutes(4));
        await Assert.That(await authentication.GetAuthenticatedIdentityAsync(result.SessionId!))
            .IsEqualTo(result.IdentityId);

        clock.Advance(TimeSpan.FromMinutes(6));
        await Assert.That(await authentication.GetAuthenticatedIdentityAsync(result.SessionId!)).IsNull();
    }

    [Test]
    public async Task RevokeGrants_EndsEverySession()
    {
        await using var provider = OAuthTestHost.CreateProvider();
        var authentication = provider.GetRequiredService<IAuthenticationService>();
        var first = await authentication.RegisterAsync("frank", "correct horse");
        await Assert.That(await authentication.GetAuthenticatedIdentityAsync(first.SessionId!))
            .IsEqualTo(first.IdentityId);

        await authentication.RevokeGrantsAsync(first.IdentityId!.Value);
        await Assert.That(await authentication.GetAuthenticatedIdentityAsync(first.SessionId!)).IsNull();
    }

    [Test]
    public async Task ChangePassword_RequiresCurrentPassword_ThenAcceptsOnlyTheNewSecret()
    {
        await using var provider = OAuthTestHost.CreateProvider();
        var authentication = provider.GetRequiredService<IAuthenticationService>();
        var registered = await authentication.RegisterAsync("frank", "correct horse", createSession: false);
        var wrong = await authentication.ChangePasswordAsync("frank", "nope", "battery staple");
        await Assert.That(wrong.Succeeded).IsFalse();
        await Assert.That(wrong.Error).IsEqualTo("invalid_credentials");
        await Assert.That((await authentication.SignInAsync("frank", "correct horse", createSession: false)).Succeeded)
            .IsTrue();

        var changed = await authentication.ChangePasswordAsync("frank", "correct horse", "battery staple");
        await Assert.That(changed.Succeeded).IsTrue();
        await Assert.That(changed.IdentityId).IsEqualTo(registered.IdentityId);
        await Assert.That((await authentication.SignInAsync("frank", "correct horse", createSession: false)).Succeeded)
            .IsFalse();
        await Assert.That((await authentication.SignInAsync("frank", "battery staple", createSession: false)).Succeeded)
            .IsTrue();
    }

    [Test]
    public async Task RegisterAndChangePassword_RejectForbiddenFragments()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.Configure<PasswordHasherOptions>(OAuthTestHost.FastArgon);
        services.AddSingleton<IPasswordBreachChecker>(_ => AllowingPasswordBreachChecker.Instance);
        services.AddNovolisAuthentication(o =>
        {
            o.IsDevelopment = true;
            o.ForbiddenPasswordFragments = ["novolis"];
        });
        await using var provider = services.BuildServiceProvider();
        var authentication = provider.GetRequiredService<IAuthenticationService>();
        var identifier = await authentication.RegisterAsync("frank", "frankhorse");
        await Assert.That(identifier.Error).IsEqualTo("password_forbidden");
        var product = await authentication.RegisterAsync("frank", "novolis-secret");
        await Assert.That(product.Error).IsEqualTo("password_forbidden");
        var ok = await authentication.RegisterAsync("frank", "correct horse", createSession: false);
        await Assert.That(ok.Succeeded).IsTrue();
        var change = await authentication.ChangePasswordAsync("frank", "correct horse", "novolis-next");
        await Assert.That(change.Error).IsEqualTo("password_forbidden");
    }

    [Test]
    public async Task CredentialAndIdentity_HaveNoKnowledgeBasedRecoveryFields()
    {
        string[] forbidden =
        [
            "PasswordHint", "Hint", "SecurityQuestion", "SecretQuestion", "SecretAnswer", "KnowledgeAnswer",
        ];
        foreach (var name in forbidden)
        {
            await Assert.That(typeof(CredentialRecord).GetProperty(name)).IsNull();
            await Assert.That(typeof(IdentityRecord).GetProperty(name)).IsNull();
        }
    }

    [Test]
    public async Task Register_Production_RequiresBreachChecker()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.Configure<PasswordHasherOptions>(OAuthTestHost.FastArgon);
        services.AddNovolisAuthentication(o => o.IsDevelopment = false);
        await using var provider = services.BuildServiceProvider();
        var authentication = provider.GetRequiredService<IAuthenticationService>();
        await Assert.That(async () => await authentication.RegisterAsync("frank", "correct horse"))
            .Throws<InvalidOperationException>();
    }

    sealed class ManualTimeProvider : TimeProvider
    {
        DateTimeOffset _utc = DateTimeOffset.UtcNow;

        public void Advance(TimeSpan delta) => _utc += delta;

        public override DateTimeOffset GetUtcNow() => _utc;
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
