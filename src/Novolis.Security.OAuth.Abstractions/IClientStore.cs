namespace Novolis.Security.OAuth;

/// <summary>Looks up OAuth clients by public <c>client_id</c>.</summary>
public interface IClientStore
{
    /// <summary>Finds a client by exact <paramref name="clientId"/>.</summary>
    ValueTask<OAuthClient?> FindByClientIdAsync(string clientId, CancellationToken ct = default);

    /// <summary>Inserts or replaces a client.</summary>
    ValueTask UpsertAsync(OAuthClient client, CancellationToken ct = default);
}
