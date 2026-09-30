using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Novolis.Security.OAuth;

/// <summary>ES384 key ring with one current signer and historical validation keys.</summary>
public sealed class SigningKeyRing
{
    internal const string DevelopmentPemForbidden = "Ephemeral or Development signing keys are forbidden outside Development.";

    readonly OAuthOptions _options;
    readonly IKeyStore _store;
    readonly ILogger<SigningKeyRing> _logger;
    readonly TimeProvider _time;
    readonly Lock _gate = new();
    ECDsaSecurityKey? _signing;
    IReadOnlyList<SecurityKey> _validation = [];

    /// <summary>Creates a key ring.</summary>
    public SigningKeyRing(
        IOptions<OAuthOptions> options,
        IKeyStore store,
        ILogger<SigningKeyRing> logger,
        TimeProvider time)
    {
        _options = options.Value;
        _store = store;
        _logger = logger;
        _time = time;
    }

    /// <summary>Credentials for minting ES384 access tokens.</summary>
    public SigningCredentials GetSigningCredentials()
    {
        EnsureLoaded();
        return new SigningCredentials(_signing!, SecurityAlgorithms.EcdsaSha384);
    }

    /// <summary>Public and historical keys for JWT validation.</summary>
    public IReadOnlyList<SecurityKey> GetValidationKeys()
    {
        EnsureLoaded();
        return _validation;
    }

    /// <summary>Public JWKS document with no private key material.</summary>
    public JsonWebKeySet GetJsonWebKeySet()
    {
        EnsureLoaded();
        var set = new JsonWebKeySet();
        foreach (var key in _validation)
        {
            var jwk = key switch
            {
                JsonWebKey jsonWebKey => new JsonWebKey(jsonWebKey.ToString()),
                ECDsaSecurityKey ecdsa => JsonWebKeyConverter.ConvertFromECDsaSecurityKey(ToPublic(ecdsa)),
                _ => null,
            };
            if (jwk is null)
                continue;

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

            var now = _time.GetUtcNow();
            var stored = _store.GetActiveAsync(now).AsTask().GetAwaiter().GetResult()
                .Where(k => string.Equals(k.Alg, SecurityAlgorithms.EcdsaSha384, StringComparison.Ordinal))
                .ToArray();
            var validation = new List<SecurityKey>();

            foreach (var record in stored)
            {
                var key = LoadValidationKey(record);
                if (key is not null)
                    validation.Add(key);
            }

            if (!string.IsNullOrWhiteSpace(_options.SigningKeyPem))
            {
                _signing = LoadPrivateKey(_options.SigningKeyPem, _options.SigningKeyKid);
                validation.Insert(0, ToPublic(_signing));
            }
            else
            {
                var current = _store.GetCurrentAsync(now).AsTask().GetAwaiter().GetResult()
                    ?? stored.FirstOrDefault(k => k.Current && !string.IsNullOrWhiteSpace(k.PrivatePem))
                    ?? stored.Where(k => !string.IsNullOrWhiteSpace(k.PrivatePem))
                        .OrderByDescending(k => k.CreatedUtc)
                        .FirstOrDefault();

                if (current is not null && !string.IsNullOrWhiteSpace(current.PrivatePem))
                {
                    _signing = LoadPrivateKey(current.PrivatePem!, current.Kid);
                }
                else if (_options.IsDevelopment && _options.AllowEphemeralSigningKey)
                {
                    _logger.LogWarning("Generating an ephemeral ECDSA P-384 signing key. Tokens will not survive process restart.");
                    var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
                    _signing = new ECDsaSecurityKey(ecdsa) { KeyId = StableKid(ecdsa) };
                    validation.Insert(0, ToPublic(_signing));
                }
                else
                {
                    if (!_options.IsDevelopment && _options.AllowEphemeralSigningKey)
                        throw new InvalidOperationException(DevelopmentPemForbidden);

                    throw new InvalidOperationException(
                        "OAuthOptions.SigningKeyPem or a signing-key store private key is required outside Development.");
                }
            }

            if (_signing is not null && validation.All(k => !string.Equals(k.KeyId, _signing.KeyId, StringComparison.Ordinal)))
                validation.Insert(0, ToPublic(_signing));

            _validation = validation
                .GroupBy(k => k.KeyId ?? "", StringComparer.Ordinal)
                .Select(g => g.First())
                .ToArray();
        }
    }

    /// <summary>
    /// Installs a new ES384 current signer and keeps previous keys for validation until they expire from JWKS.
    /// </summary>
    public async ValueTask RotateAsync(
        string pem,
        string? kid = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(pem);
        var next = LoadPrivateKey(pem, kid);
        var now = _time.GetUtcNow();
        EnsureLoaded();
        var previous = _signing;

        var active = await _store.GetActiveAsync(now, cancellationToken).ConfigureAwait(false);
        foreach (var key in active.Where(item => item.Current))
        {
            key.Current = false;
            await _store.UpsertAsync(key, cancellationToken).ConfigureAwait(false);
        }

        var pub = ToPublic(next);
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(pub);
        jwk.D = null;
        jwk.Use = "sig";
        jwk.Alg = SecurityAlgorithms.EcdsaSha384;
        await _store.UpsertAsync(
            new SigningKeyRecord
            {
                Id = Guid.NewGuid(),
                Kid = next.KeyId ?? "",
                Alg = SecurityAlgorithms.EcdsaSha384,
                PublicJwk = JsonSerializer.Serialize(new Dictionary<string, string?>
                {
                    ["kty"] = jwk.Kty,
                    ["crv"] = jwk.Crv,
                    ["x"] = jwk.X,
                    ["y"] = jwk.Y,
                    ["kid"] = jwk.Kid ?? next.KeyId,
                    ["use"] = "sig",
                    ["alg"] = SecurityAlgorithms.EcdsaSha384,
                }),
                PrivatePem = pem,
                CreatedUtc = now,
                Enabled = true,
                Current = true,
            },
            cancellationToken).ConfigureAwait(false);

        lock (_gate)
        {
            _signing = next;
            var keys = _validation.ToList();
            if (previous is not null)
                keys.Add(ToPublic(previous));
            keys.Insert(0, pub);
            _validation = keys
                .GroupBy(k => k.KeyId ?? "", StringComparer.Ordinal)
                .Select(g => g.First())
                .ToArray();
        }

        _logger.LogInformation("Rotated OAuth signing key to kid={Kid}.", next.KeyId);
    }

    static ECDsaSecurityKey LoadPrivateKey(string pem, string? kid)
    {
        var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(pem);
        if (ecdsa.KeySize != 384)
            throw new InvalidOperationException("Signing keys must be ECDSA P-384 (ES384).");

        return new ECDsaSecurityKey(ecdsa) { KeyId = string.IsNullOrWhiteSpace(kid) ? StableKid(ecdsa) : kid };
    }

    static SecurityKey? LoadValidationKey(SigningKeyRecord record)
    {
        if (!string.IsNullOrWhiteSpace(record.PrivatePem))
            return ToPublic(LoadPrivateKey(record.PrivatePem!, record.Kid));
        if (string.IsNullOrWhiteSpace(record.PublicJwk))
            return null;

        var jwk = new JsonWebKey(record.PublicJwk) { KeyId = record.Kid };
        return jwk;
    }

    static ECDsaSecurityKey ToPublic(ECDsaSecurityKey key)
    {
        var parameters = key.ECDsa.ExportParameters(includePrivateParameters: false);
        var pub = ECDsa.Create(parameters);
        return new ECDsaSecurityKey(pub) { KeyId = key.KeyId };
    }

    static string StableKid(ECDsa ecdsa)
    {
        var parameters = ecdsa.ExportParameters(includePrivateParameters: false);
        var material = new byte[parameters.Q.X!.Length + parameters.Q.Y!.Length];
        parameters.Q.X.CopyTo(material, 0);
        parameters.Q.Y.CopyTo(material, parameters.Q.X.Length);
        return Base64UrlEncoder.Encode(SHA256.HashData(material))[..22];
    }
}