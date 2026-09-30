using Novolis.Security.Authentication;

namespace Novolis.Security.OAuth.Storage;

internal static class OAuthStorageMapper
{
    const char PackSeparator = '\u001f';

    public static StoredOAuthClient ToStored(OAuthClient client) => new()
    {
        Id = client.Id,
        ClientId = client.ClientId,
        ClientType = (int)client.ClientType,
        SecretHash = client.SecretHash,
        Disabled = client.Disabled,
        AllowedGrantTypes = Pack(client.AllowedGrantTypes),
        AllowedRedirectUris = Pack(client.AllowedRedirectUris),
        AllowedScopes = Pack(client.AllowedScopes),
        AllowedAudiences = Pack(client.AllowedAudiences),
    };

    public static OAuthClient ToClient(StoredOAuthClient row) => new()
    {
        Id = row.Id,
        ClientId = row.ClientId,
        ClientType = (OAuthClientType)row.ClientType,
        SecretHash = row.SecretHash,
        Disabled = row.Disabled,
        AllowedGrantTypes = Unpack(row.AllowedGrantTypes),
        AllowedRedirectUris = Unpack(row.AllowedRedirectUris),
        AllowedScopes = Unpack(row.AllowedScopes),
        AllowedAudiences = Unpack(row.AllowedAudiences),
    };

    public static StoredRefreshToken ToStored(RefreshTokenRecord token) => new()
    {
        Id = token.Id,
        FamilyId = token.FamilyId,
        IdentityId = token.IdentityId.Value,
        ClientId = token.ClientId,
        ClientPublicId = token.ClientPublicId,
        SecretHash = token.SecretHash,
        Scope = token.Scope,
        Audience = token.Audience,
        CreatedUtc = token.CreatedUtc,
        ExpiresUtc = token.ExpiresUtc,
        RevokedUtc = token.RevokedUtc,
        ReplacedById = token.ReplacedById,
        FamilyExpiresUtc = token.FamilyExpiresUtc,
        CnfJkt = token.CnfJkt,
        CnfX5tS256 = token.CnfX5tS256,
    };

    public static RefreshTokenRecord ToRefresh(StoredRefreshToken row) => new()
    {
        Id = row.Id,
        FamilyId = row.FamilyId,
        IdentityId = IdentityId.FromGuid(row.IdentityId),
        ClientId = row.ClientId,
        ClientPublicId = row.ClientPublicId,
        SecretHash = row.SecretHash,
        Scope = row.Scope,
        Audience = row.Audience,
        CreatedUtc = row.CreatedUtc,
        ExpiresUtc = row.ExpiresUtc,
        RevokedUtc = row.RevokedUtc,
        ReplacedById = row.ReplacedById,
        FamilyExpiresUtc = row.FamilyExpiresUtc,
        CnfJkt = row.CnfJkt,
        CnfX5tS256 = row.CnfX5tS256,
    };

    public static StoredAuthorizationCode ToStored(AuthorizationCodeRecord code) => new()
    {
        Id = code.Id,
        SecretHash = code.SecretHash,
        ClientId = code.ClientId,
        IdentityId = code.IdentityId.Value,
        RedirectUri = code.RedirectUri,
        CodeChallenge = code.CodeChallenge,
        CodeChallengeMethod = code.CodeChallengeMethod,
        Scope = code.Scope,
        Audience = code.Audience,
        IssuedUtc = code.IssuedUtc,
        ExpiresUtc = code.ExpiresUtc,
        ConsumedUtc = code.ConsumedUtc,
        AccessTokenJti = code.AccessTokenJti,
        RefreshFamilyId = code.RefreshFamilyId,
    };

    public static AuthorizationCodeRecord ToCode(StoredAuthorizationCode row) => new()
    {
        Id = row.Id,
        SecretHash = row.SecretHash,
        ClientId = row.ClientId,
        IdentityId = IdentityId.FromGuid(row.IdentityId),
        RedirectUri = row.RedirectUri,
        CodeChallenge = row.CodeChallenge,
        CodeChallengeMethod = row.CodeChallengeMethod,
        Scope = row.Scope,
        Audience = row.Audience,
        IssuedUtc = row.IssuedUtc,
        ExpiresUtc = row.ExpiresUtc,
        ConsumedUtc = row.ConsumedUtc,
        AccessTokenJti = row.AccessTokenJti,
        RefreshFamilyId = row.RefreshFamilyId,
    };

    public static StoredSigningKey ToStored(SigningKeyRecord key) => new()
    {
        Id = key.Id,
        Kid = key.Kid,
        Alg = key.Alg,
        PublicJwk = key.PublicJwk,
        PrivatePem = key.PrivatePem,
        PrivatePemCipher = key.PrivatePemCipher,
        CreatedUtc = key.CreatedUtc,
        NotBeforeUtc = key.NotBeforeUtc,
        NotAfterUtc = key.NotAfterUtc,
        Enabled = key.Enabled,
        Current = key.Current,
    };

    public static SigningKeyRecord ToKey(StoredSigningKey row) => new()
    {
        Id = row.Id,
        Kid = row.Kid,
        Alg = row.Alg,
        PublicJwk = row.PublicJwk,
        PrivatePem = row.PrivatePem,
        PrivatePemCipher = row.PrivatePemCipher,
        CreatedUtc = row.CreatedUtc,
        NotBeforeUtc = row.NotBeforeUtc,
        NotAfterUtc = row.NotAfterUtc,
        Enabled = row.Enabled,
        Current = row.Current,
    };

    static string Pack(IEnumerable<string> values) =>
        string.Join(PackSeparator, values.Where(v => !string.IsNullOrWhiteSpace(v)));

    static List<string> Unpack(string packed) =>
        string.IsNullOrEmpty(packed)
            ? []
            : packed.Split(PackSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .ToList();
}
