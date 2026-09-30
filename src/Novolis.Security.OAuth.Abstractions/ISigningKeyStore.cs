namespace Novolis.Security.OAuth;

/// <summary>Signing-key persistence. Alias of <see cref="IKeyStore"/> kept so existing DI registrations compile.</summary>
public interface ISigningKeyStore : IKeyStore
{
}
