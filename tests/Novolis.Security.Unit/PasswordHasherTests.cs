using Microsoft.Extensions.Options;
using Novolis.Security.PasswordHashing;
using TUnit.Core;

namespace Novolis.Security.Tests;

public class PasswordHasherTests
{
    static PasswordHasher CreateHasher() =>
        new(Options.Create(new PasswordHasherOptions
        {
            MemorySizeKiB = 32,
            Iterations = 1,
            DegreeOfParallelism = 1,
        }));

    [Test]
    public async Task HashPassword_RoundTrips()
    {
        var hasher = CreateHasher();
        var hash = hasher.HashPassword("correct horse battery staple");

        await Assert.That(hash).StartsWith("$argon2id$v=19$");
        await Assert.That(hasher.CompareHashedPassword(hash, "correct horse battery staple")).IsTrue();
    }

    [Test]
    public async Task CompareHashedPassword_RejectsWrongPassword()
    {
        var hasher = CreateHasher();
        var hash = hasher.HashPassword("correct horse battery staple");
        await Assert.That(hasher.CompareHashedPassword(hash, "wrong")).IsFalse();
    }

    [Test]
    public async Task CompareHashedPassword_RejectsGarbage()
    {
        var hasher = CreateHasher();
        await Assert.That(hasher.CompareHashedPassword("not-a-hash", "password")).IsFalse();
    }

    [Test]
    public async Task CompareHashedPassword_RejectsArgon2iAndNullBytes()
    {
        var hasher = CreateHasher();
        var hash = hasher.HashPassword("pw");
        await Assert.That(hasher.CompareHashedPassword(
            "$argon2i$v=19$m=32,t=1,p=1$YWFhYWFhYWE$YmJiYmJiYmJiYmJiYmJiYg",
            "pw")).IsFalse();
        await Assert.That(hasher.CompareHashedPassword(hash, "pw\0admin")).IsFalse();
        await Assert.That(hasher.CompareHashedPassword(hash, "pw")).IsTrue();
    }

    [Test]
    public async Task CompareHashedPassword_AcceptsNfcAndNfdOfSameCharacter()
    {
        var hasher = CreateHasher();
        var nfc = "café";
        var nfd = "cafe\u0301";
        var hash = hasher.HashPassword(nfd);
        await Assert.That(hasher.CompareHashedPassword(hash, nfc)).IsTrue();
        await Assert.That(hasher.CompareHashedPassword(hash, nfd)).IsTrue();
    }
}
