namespace Novolis.Security.Secrets;

public interface ISecretGenerator
{
    string GenerateCharsetSecret(SecretGeneratorOptions? options = null);

    string GenerateWordPassphrase(PassphraseOptions? options = null);
}
