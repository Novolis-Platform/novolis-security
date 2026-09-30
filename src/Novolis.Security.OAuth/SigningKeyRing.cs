using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Novolis.Security.OAuth;

/// <summary>Loads ECDSA P-384 signing material from PEM, the key store, or an ephemeral Development key.</summary>
public sealed class SigningKeyRing
{
    internal const string DevelopmentPemForbidden = "Ephemeral or Development signing keys are forbidden outside Development.";

    readonly OAuthOptions _options;
    readonly ISigningKeyStore _store;
    readonly ILogger<SigningKeyRing> _logger;
    readonly Lock _gate = new();
    ECDsaSecurityKey? _signing;
    IReadOnlyList<ECDsaSecurityKey> _validation = [];

    /// <summary>Creates a key ring.</summary>
    public SigningKeyRing(IOptions<OAuthOptions> options, ISigningKeyStore store, ILogger<SigningKeyRing> logger)
    {
        _options = options.Value;
        _store = store;
        _logger = logger;
    }

    /// <summary>Credentials for minting ES384 access tokens.</summary>
    public SigningCredentials GetSigningCredentials()
    {
        EnsureLoaded();
        return new SigningCredentials(_signing!, SecurityAlgorithms.EcdsaSha384);
    }

    /// <summary>Public keys for JWT validation and JWKS.</summary>
    public IReadOnlyList<ECDsaSecurityKey> GetValidationKeys()
    {
        EnsureLoaded();
        return _validation;
    }

    /// <summary>Public JWKS document (no private parameters).</summary>
    public JsonWebKeySet GetJsonWebKeySet()
    {
        var set = new JsonWebKeySet();
        foreach (var key in GetValidationKeys())
        {
            var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(ToPublic(key));
            jwk.Use = "sig";
            jwk.Alg = SecurityAlgorithms.EcdsaSha384;
            jwk.D = null;
            set.Keys.Add(jwk);
        }

        return set;
    }

    void EnsureLoaded()
    {
        if (_signing is not null)
            return;

        lock (_gate)
        {
            if (_signing is not null)
                return;

            if (!string.IsNullOrWhiteSpace(_options.SigningKeyPem))
            {
                LoadFromPem(_options.SigningKeyPem, _options.SigningKeyKid);
                return;
            }

            var stored = _store.GetActiveAsync().AsTask().GetAwaiter().GetResult();
            var withPrivate = stored.FirstOrDefault(k => !string.IsNullOrWhiteSpace(k.PrivatePem));
            if (withPrivate is not null)
            {
                LoadFromPem(withPrivate.PrivatePem!, withPrivate.Kid);
                return;
            }

            if (_options.IsDevelopment && _options.AllowEphemeralSigningKey)
            {
                _logger.LogWarning("Generating an ephemeral ECDSA P-384 signing key. Tokens will not survive process restart.");
                var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
                var kid = Guid.CreateVersion7().ToString("N");
                _signing = new ECDsaSecurityKey(ecdsa) { KeyId = kid };
                _validation = [_signing];
                return;
            }

            if (!_options.IsDevelopment && _options.AllowEphemeralSigningKey)
                throw new InvalidOperationException(DevelopmentPemForbidden);

            throw new InvalidOperationException(
                "OAuthOptions.SigningKeyPem or a signing-key store private PEM is required outside Development.");
        }
    }

    void LoadFromPem(string pem, string? kid)
    {
        var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(pem);
        if (ecdsa.KeySize != 384)
            throw new InvalidOperationException("Signing keys must be ECDSA P-384 (ES384).");

        kid ??= Guid.CreateVersion7().ToString("N");
        _signing = new ECDsaSecurityKey(ecdsa) { KeyId = kid };
        _validation = [_signing];
    }

    static ECDsaSecurityKey ToPublic(ECDsaSecurityKey key)
    {
        var parameters = key.ECDsa.ExportParameters(includePrivateParameters: false);
        var pub = ECDsa.Create(parameters);
        return new ECDsaSecurityKey(pub) { KeyId = key.KeyId };
    }
}
