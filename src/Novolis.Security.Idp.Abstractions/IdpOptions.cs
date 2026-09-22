namespace Novolis.Security.Idp;

/// <summary>Issuer, audience, lifetime, and signing configuration for the limited IDP.</summary>
public sealed class IdpOptions
{
    /// <summary>JWT <c>iss</c> and discovery issuer. Must be an absolute URI in production hosts.</summary>
    public string Issuer { get; set; } = "https://idp.novolis.local";

    /// <summary>Accepted JWT audiences. The first value is written as <c>aud</c>.</summary>
    public IList<string> Audiences { get; set; } = ["novolis"];

    /// <summary>Access-token lifetime. Default 15 minutes.</summary>
    public TimeSpan AccessTokenLifetime { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>Refresh-token lifetime. Default 7 days.</summary>
    public TimeSpan RefreshTokenLifetime { get; set; } = TimeSpan.FromDays(7);

    /// <summary>Clock skew applied when validating tokens. Default 30 seconds.</summary>
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Optional PKCS#8 PEM for ECDSA P-384. Required outside Development unless the key store already has private material.</summary>
    public string? SigningKeyPem { get; set; }

    /// <summary>Key id for <see cref="SigningKeyPem"/>. Generated when omitted.</summary>
    public string? SigningKeyKid { get; set; }

    /// <summary>When true, the host is treated as Development (ephemeral P-384 is allowed if no PEM/store key exists).</summary>
    public bool IsDevelopment { get; set; }

    /// <summary>
    /// When true with <see cref="IsDevelopment"/>, generate an in-process ECDSA P-384 key.
    /// Forbidden when <see cref="IsDevelopment"/> is false.
    /// </summary>
    public bool AllowEphemeralSigningKey { get; set; }
}
