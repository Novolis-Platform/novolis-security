namespace Novolis.Security.OAuth;

/// <summary>Issuer, token lifetime, client, and signing-key configuration.</summary>
public sealed class OAuthOptions
{
    /// <summary>JWT issuer and RFC 8414 metadata issuer.</summary>
    public Uri Issuer { get; set; } = new("https://accounts.novolis.local");

    /// <summary>Configured audiences used when a client does not narrow the request.</summary>
    public IList<string> Audiences { get; set; } = ["novolis"];

    /// <summary>Access-token lifetime. Short-lived access tokens are the default.</summary>
    public TimeSpan AccessTokenLifetime { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>Rotating refresh-token lifetime.</summary>
    public TimeSpan RefreshTokenLifetime { get; set; } = TimeSpan.FromDays(7);

    /// <summary>Authorization-code lifetime.</summary>
    public TimeSpan AuthorizationCodeLifetime { get; set; } = TimeSpan.FromMinutes(2);

    /// <summary>Clock skew used for token, code, and key validation.</summary>
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Optional PKCS#8 PEM for an ECDSA P-384 signing key.</summary>
    public string? SigningKeyPem { get; set; }

    /// <summary>Stable key id for <see cref="SigningKeyPem"/>.</summary>
    public string? SigningKeyKid { get; set; }

    /// <summary>Whether the host is running in Development.</summary>
    public bool IsDevelopment { get; set; }

    /// <summary>Allows an ephemeral P-384 key only when <see cref="IsDevelopment"/> is true.</summary>
    public bool AllowEphemeralSigningKey { get; set; }

    /// <summary>Token endpoint attempts per client and window.</summary>
    public int TokenAttemptsPerWindow { get; set; } = 30;

    /// <summary>Token endpoint attempt window.</summary>
    public TimeSpan TokenAttemptWindow { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>Whether to advertise the compatibility metadata alias.</summary>
    public bool EnableOpenIdConfigurationAlias { get; set; }

    /// <summary>
    /// When true, the token endpoint uses the left-most <c>X-Forwarded-For</c> value as the remote address.
    /// Leave false unless a trusted reverse proxy is stripping untrusted forwarded headers.
    /// </summary>
    public bool TrustForwardedFor { get; set; }

    /// <summary>
    /// Allows in-memory OAuth stores and the no-op event sink outside Development.
    /// Production hosts must not set this.
    /// </summary>
    public bool AllowInMemoryStores { get; set; }
}
