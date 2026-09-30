using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Novolis.Security.Authentication;
using Novolis.Security.Authentication.Storage;
using Novolis.Security.Authorization;
using Novolis.Security.OAuth;
using Novolis.Storage.Abstractions;
using TUnit.Core;

namespace Novolis.Security.Tests;

/// <summary>
/// Reference identity host for OWASP checks that need durable stores:
/// credential isolation, Authorization Code + S256 PKCE, refresh reuse, and tenant authorization.
/// </summary>
public class OwaspReferenceScenarioTests
{
    const string Email = "frank@example.com";
    const string Password = "correct horse battery staple";
    const string ConfidentialId = "space-game-web";
    const string OtherClientId = "space-game-other";
    const string PublicClientId = "space-game-launcher";
    const string ClientSecret = "client-secret";
    const string RedirectUri = "https://game.example/callback";

    [Test]
    public async Task JsonStores_ReferenceScenario()
    {
        var root = Path.Combine(Path.GetTempPath(), "novolis-owasp-json-" + Guid.NewGuid().ToString("N"));
        try
        {
            var services = new ServiceCollection();
            services.AddReferenceIdentity();
            services.AddNovolisAuthorization();
            services.AddPermission<Play>();
            services.AddBuiltInRole<Player>();
            services.AddJsonStores(root);
            services.AddDurableIdentityStores();
            await using var provider = services.BuildServiceProvider();
            await RunScenarioAsync(provider, root);
        }
        finally
        {
            if (Directory.Exists(root))
                Directory.Delete(root, recursive: true);
        }
    }

    [Test]
    public async Task SqliteStores_ReferenceScenario()
    {
        var db = Path.Combine(Path.GetTempPath(), "novolis-owasp-" + Guid.NewGuid().ToString("N") + ".db");
        try
        {
            var services = new ServiceCollection();
            services.AddReferenceIdentity();
            services.AddNovolisAuthorization();
            services.AddPermission<Play>();
            services.AddBuiltInRole<Player>();
            services.AddSqliteStores("Data Source=" + db + ";Pooling=False");
            services.AddDurableIdentityStores();
            await using var provider = services.BuildServiceProvider();
            await RunScenarioAsync(provider, jsonRoot: null);
        }
        finally
        {
            TryDelete(db);
        }
    }

    static async Task RunScenarioAsync(ServiceProvider provider, string? jsonRoot)
    {
        await SeedClientsAsync(provider);
        var authentication = provider.GetRequiredService<IAuthenticationService>();
        var identities = provider.GetRequiredService<IIdentityStore>();
        var tokens = provider.GetRequiredService<OAuthTokenService>();

        var registered = await authentication.RegisterAsync(Email, Password);
        await Assert.That(registered.Succeeded).IsTrue();
        var identityId = registered.IdentityId!.Value;
        var firstSession = registered.SessionId!;

        await AssertStoredIsolationAsync(provider, identityId, jsonRoot);

        var shortPassword = await authentication.RegisterAsync("short-user", "x", createSession: false);
        await Assert.That(shortPassword.Succeeded).IsTrue();

        var second = await authentication.SignInAsync(Email, Password);
        await Assert.That(second.SessionId).IsNotEqualTo(firstSession);
        await Assert.That(await authentication.GetAuthenticatedIdentityAsync(firstSession)).IsEqualTo(identityId);
        await authentication.SignOutAsync(second.SessionId!);
        await Assert.That(await authentication.GetAuthenticatedIdentityAsync(second.SessionId!)).IsNull();
        await Assert.That(await authentication.GetAuthenticatedIdentityAsync(firstSession)).IsEqualTo(identityId);

        var (verifier, challenge) = CreatePkce();
        var code = await tokens.IssueAuthorizationCodeAsync(CodeRequest(ConfidentialId, identityId, challenge, "S256"));
        await Assert.That(code.Succeeded).IsTrue();

        var issued = await tokens.IssueAsync(Redeem(ConfidentialId, ClientSecret, code.Code!, verifier, RedirectUri));
        await Assert.That(issued.Succeeded).IsTrue();
        await Assert.That(issued.TokenType).IsEqualTo("Bearer");
        await Assert.That(issued.RefreshToken).IsNotNull();
        await Assert.That(issued.IdentityId).IsEqualTo(identityId);
        AssertAccessTokenClaims(issued.AccessToken!, identityId);

        var validated = await tokens.ValidateAsync(issued.AccessToken!);
        await Assert.That(validated.IsValid).IsTrue();

        var replay = await tokens.IssueAsync(Redeem(ConfidentialId, ClientSecret, code.Code!, verifier, RedirectUri));
        await Assert.That(replay.Error).IsEqualTo(OAuthTokenErrors.InvalidGrant);

        var (verifier2, challenge2) = CreatePkce();
        var code2 = await tokens.IssueAuthorizationCodeAsync(CodeRequest(ConfidentialId, identityId, challenge2, "S256"));
        var wrongRedirect = await tokens.IssueAsync(Redeem(
            ConfidentialId, ClientSecret, code2.Code!, verifier2, RedirectUri + "/extra"));
        await Assert.That(wrongRedirect.Error).IsEqualTo(OAuthTokenErrors.InvalidGrant);

        var (verifier3, challenge3) = CreatePkce();
        var bound = await tokens.IssueAuthorizationCodeAsync(CodeRequest(ConfidentialId, identityId, challenge3, "S256"));
        var otherClient = await tokens.IssueAsync(Redeem(OtherClientId, ClientSecret, bound.Code!, verifier3, RedirectUri));
        await Assert.That(otherClient.Error).IsEqualTo(OAuthTokenErrors.InvalidGrant);

        var openRedirect = await tokens.IssueAuthorizationCodeAsync(new AuthorizationCodeIssueRequest
        {
            ClientId = ConfidentialId,
            RedirectUri = "https://evil.example/callback",
            IdentityId = identityId,
            Scope = "game",
            Audience = "space-game-api",
            CodeChallenge = challenge3,
            CodeChallengeMethod = "S256",
        });
        await Assert.That(openRedirect.Succeeded).IsFalse();

        var prefixRedirect = await tokens.IssueAuthorizationCodeAsync(new AuthorizationCodeIssueRequest
        {
            ClientId = ConfidentialId,
            RedirectUri = "https://game.example/callback.evil",
            IdentityId = identityId,
            Scope = "game",
            Audience = "space-game-api",
            CodeChallenge = challenge3,
            CodeChallengeMethod = "S256",
        });
        await Assert.That(prefixRedirect.Succeeded).IsFalse();

        var plain = await tokens.IssueAuthorizationCodeAsync(CodeRequest(ConfidentialId, identityId, challenge3, "plain"));
        await Assert.That(plain.Succeeded).IsFalse();

        foreach (var grant in new[] { "password", "implicit", "urn:ietf:params:oauth:grant-type:device_code" })
        {
            var denied = await tokens.IssueAsync(new TokenIssueRequest
            {
                GrantType = grant,
                ClientId = ConfidentialId,
                ClientSecret = ClientSecret,
            });
            await Assert.That(denied.Error).IsEqualTo(OAuthTokenErrors.UnsupportedGrantType);
        }

        var publicCredentials = await tokens.IssueAsync(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.ClientCredentials,
            ClientId = PublicClientId,
        });
        await Assert.That(publicCredentials.Error).IsEqualTo(OAuthTokenErrors.UnauthorizedClient);

        var (publicVerifier, publicChallenge) = CreatePkce();
        var publicCode = await tokens.IssueAuthorizationCodeAsync(
            CodeRequest(PublicClientId, identityId, publicChallenge, "S256", "https://launcher.example/callback"));
        await Assert.That(publicCode.Succeeded).IsTrue();
        var publicTokens = await tokens.IssueAsync(Redeem(
            PublicClientId, clientSecret: null, publicCode.Code!, publicVerifier, "https://launcher.example/callback"));
        await Assert.That(publicTokens.Succeeded).IsTrue();
        var publicWithSecret = await tokens.IssueAsync(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.ClientCredentials,
            ClientId = PublicClientId,
            ClientSecret = "not-a-secret",
        });
        await Assert.That(publicWithSecret.Error).IsEqualTo(OAuthTokenErrors.InvalidClient);

        var elevated = await tokens.IssueAsync(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.RefreshToken,
            ClientId = ConfidentialId,
            ClientSecret = ClientSecret,
            RefreshToken = issued.RefreshToken,
            Scope = "game admin",
        });
        await Assert.That(elevated.Error).IsEqualTo(OAuthTokenErrors.InvalidScope);

        var refreshed = await tokens.IssueAsync(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.RefreshToken,
            ClientId = ConfidentialId,
            ClientSecret = ClientSecret,
            RefreshToken = issued.RefreshToken,
        });
        await Assert.That(refreshed.Succeeded).IsTrue();
        var reuse = await tokens.IssueAsync(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.RefreshToken,
            ClientId = ConfidentialId,
            ClientSecret = ClientSecret,
            RefreshToken = issued.RefreshToken,
        });
        await Assert.That(reuse.Error).IsEqualTo(OAuthTokenErrors.InvalidGrant);
        var family = await tokens.IssueAsync(new TokenIssueRequest
        {
            GrantType = OAuthGrantTypes.RefreshToken,
            ClientId = ConfidentialId,
            ClientSecret = ClientSecret,
            RefreshToken = refreshed.RefreshToken,
        });
        await Assert.That(family.Error).IsEqualTo(OAuthTokenErrors.InvalidGrant);

        await authentication.SignOutAsync(firstSession);
        await Assert.That(await authentication.GetAuthenticatedIdentityAsync(firstSession)).IsNull();
        await Assert.That((await tokens.ValidateAsync(issued.AccessToken!)).IsValid).IsTrue();

        var directory = await identities.TryGetAsync(identityId);
        directory!.Disabled = true;
        await identities.UpsertAsync(directory);
        await Assert.That((await authentication.SignInAsync(Email, Password, createSession: false)).Succeeded).IsFalse();

        var (verifier4, challenge4) = CreatePkce();
        var disabledCode = await tokens.IssueAuthorizationCodeAsync(CodeRequest(ConfidentialId, identityId, challenge4, "S256"));
        await Assert.That(disabledCode.Succeeded).IsTrue();
        var disabledRedeem = await tokens.IssueAsync(Redeem(ConfidentialId, ClientSecret, disabledCode.Code!, verifier4, RedirectUri));
        await Assert.That(disabledRedeem.Error).IsEqualTo(OAuthTokenErrors.InvalidGrant);

        var authz = provider.GetRequiredService<IAuthorizationService>();
        var tenant = TenantId.New();
        var otherTenant = TenantId.New();
        await Assert.That((await authz.AuthorizeAsync(identityId, tenant, AuthorizationIds.Permission<Play>())).Succeeded)
            .IsFalse();
        await provider.GetRequiredService<IRoleAssignmentStore>()
            .AssignIdentityAsync(new IdentityRoleAssignment(tenant, identityId, AuthorizationIds.Role<Player>()));
        await Assert.That((await authz.AuthorizeAsync(identityId, tenant, AuthorizationIds.Permission<Play>())).Succeeded)
            .IsTrue();
        await Assert.That((await authz.AuthorizeAsync(identityId, otherTenant, AuthorizationIds.Permission<Play>())).Succeeded)
            .IsFalse();
    }

    static async Task AssertStoredIsolationAsync(ServiceProvider provider, IdentityId identityId, string? jsonRoot)
    {
        var identityRows = provider.GetRequiredService<IRepository<StoredIdentity>>().All().ToArray();
        var credentialRows = provider.GetRequiredService<IRepository<StoredCredential>>().All().ToArray();
        var identity = identityRows.Single(row => row.Id == identityId.Value);
        var credential = credentialRows.Single(row => row.Reference == identity.CredentialReference);
        await Assert.That(identity.Email).IsEqualTo(Email);
        await Assert.That(credential.PasswordHash.Contains("argon2id", StringComparison.Ordinal)).IsTrue();
        await Assert.That(credential.PasswordHash.Contains(Email, StringComparison.Ordinal)).IsFalse();
        await Assert.That(credential.PasswordHash.Contains(Password, StringComparison.Ordinal)).IsFalse();

        if (jsonRoot is null)
            return;

        foreach (var file in Directory.GetFiles(jsonRoot, "*", SearchOption.AllDirectories))
        {
            var text = File.ReadAllText(file);
            var hasHash = text.Contains("argon2id", StringComparison.Ordinal);
            var hasEmail = text.Contains(Email, StringComparison.Ordinal);
            await Assert.That(hasHash && hasEmail).IsFalse();
        }
    }

    static async Task SeedClientsAsync(IServiceProvider services)
    {
        await ReferenceIdentityHost.SeedClientAsync(services);
        var hasher = services.GetRequiredService<ClientSecretHasher>();
        var clients = services.GetRequiredService<IClientStore>();
        await clients.UpsertAsync(new OAuthClient
        {
            Id = Guid.NewGuid(),
            ClientId = OtherClientId,
            ClientType = OAuthClientType.Confidential,
            SecretHash = hasher.Hash(ClientSecret),
            AllowedGrantTypes = [OAuthGrantTypes.AuthorizationCode, OAuthGrantTypes.RefreshToken],
            AllowedScopes = ["game"],
            AllowedAudiences = ["space-game-api"],
            AllowedRedirectUris = [RedirectUri],
        });
        await clients.UpsertAsync(new OAuthClient
        {
            Id = Guid.NewGuid(),
            ClientId = PublicClientId,
            ClientType = OAuthClientType.Public,
            AllowedGrantTypes = [OAuthGrantTypes.AuthorizationCode, OAuthGrantTypes.RefreshToken],
            AllowedScopes = ["game"],
            AllowedAudiences = ["space-game-api"],
            AllowedRedirectUris = ["https://launcher.example/callback"],
        });

        var stored = await clients.FindByClientIdAsync(ConfidentialId);
        await Assert.That(stored!.SecretHash.StartsWith("$novolis-client$pbkdf2-sha512$210000$", StringComparison.Ordinal))
            .IsTrue();
        await Assert.That(stored.SecretHash.Contains(ClientSecret, StringComparison.Ordinal)).IsFalse();
    }

    static AuthorizationCodeIssueRequest CodeRequest(
        string clientId,
        IdentityId identityId,
        string challenge,
        string method,
        string redirectUri = RedirectUri) =>
        new()
        {
            ClientId = clientId,
            RedirectUri = redirectUri,
            IdentityId = identityId,
            Scope = "game",
            Audience = "space-game-api",
            CodeChallenge = challenge,
            CodeChallengeMethod = method,
        };

    static TokenIssueRequest Redeem(
        string clientId,
        string? clientSecret,
        string code,
        string verifier,
        string redirectUri) =>
        new()
        {
            GrantType = OAuthGrantTypes.AuthorizationCode,
            ClientId = clientId,
            ClientSecret = clientSecret,
            AuthorizationCode = code,
            RedirectUri = redirectUri,
            CodeVerifier = verifier,
        };

    static void AssertAccessTokenClaims(string jwt, IdentityId identityId)
    {
        var parts = jwt.Split('.');
        var header = Encoding.UTF8.GetString(FromBase64Url(parts[0]));
        var payload = Encoding.UTF8.GetString(FromBase64Url(parts[1]));
        if (!header.Contains("ES384", StringComparison.Ordinal))
            throw new InvalidOperationException("Access token is not ES384.");
        if (!payload.Contains(identityId.ToString(), StringComparison.Ordinal))
            throw new InvalidOperationException("Access token subject is not the identity id.");
        if (payload.Contains(Email, StringComparison.Ordinal) || payload.Contains("password", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Access token carries a login identifier or password.");
        if (payload.Contains("\"cnf\"", StringComparison.Ordinal))
            throw new InvalidOperationException("Access token is sender-constrained.");
    }

    static (string Verifier, string Challenge) CreatePkce()
    {
        var verifier = Base64Url(RandomNumberGenerator.GetBytes(32));
        var challenge = Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        return (verifier, challenge);
    }

    static string Base64Url(byte[] data) =>
        Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    static byte[] FromBase64Url(string value)
    {
        var padded = value.Replace('-', '+').Replace('_', '/');
        padded = padded.PadRight(padded.Length + (4 - padded.Length % 4) % 4, '=');
        return Convert.FromBase64String(padded);
    }

    static void TryDelete(string db)
    {
        try
        {
            if (File.Exists(db))
                File.Delete(db);
        }
        catch (IOException)
        {
            // SqliteClient may still hold the file until process teardown.
        }
    }

    public sealed class Play : IPermission
    {
        public static string Value => "game.play";
    }

    public sealed class Player : IBuiltInRole
    {
        public static string Value => "player";

        public static IReadOnlySet<PermissionId> Permissions { get; } =
            new HashSet<PermissionId> { AuthorizationIds.Permission<Play>() };
    }
}
