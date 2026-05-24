namespace Novolis.Security.Secrets;

/// <summary>Generates random secrets and word passphrases.</summary>
public interface ISecretGenerator
{
    /// <summary>Generates a secret from a character set.</summary>
    string GenerateCharsetSecret(SecretGeneratorOptions? options = null);

    /// <summary>Generates a space-separated word passphrase.</summary>
    string GenerateWordPassphrase(PassphraseOptions? options = null);
}
