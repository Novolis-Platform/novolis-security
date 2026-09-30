using Novolis.Security.Cryptography;
using Novolis.Security.WordLists;
using TUnit.Core;

namespace Novolis.Security.Tests;

public class CryptographyPrimitiveTests
{
    [Test]
    public async Task SecureRandom_Fill_IsNonZero()
    {
        var bytes = SecureRandom.GetBytes(32);
        await Assert.That(bytes.Length).IsEqualTo(32);
        await Assert.That(bytes.Any(b => b != 0)).IsTrue();
    }

    [Test]
    public async Task ConstantTime_Equals_AndUtf8()
    {
        await Assert.That(ConstantTime.Equals([1, 2, 3], [1, 2, 3])).IsTrue();
        await Assert.That(ConstantTime.Equals([1, 2, 3], [1, 2, 4])).IsFalse();
        await Assert.That(ConstantTime.EqualsUtf8("abc", "abc")).IsTrue();
        await Assert.That(ConstantTime.EqualsUtf8("abc", "abd")).IsFalse();
        await Assert.That(ConstantTime.EqualsUtf8(null, "a")).IsFalse();
        await Assert.That(ConstantTime.EqualsUtf8(null, null)).IsTrue();
        await Assert.That(ConstantTime.EqualsUtf8("", "")).IsTrue();
    }

    [Test]
    public async Task SecureMemory_ZeroesBuffer()
    {
        var bytes = SecureRandom.GetBytes(16);
        SecureMemory.Zero(bytes);
        await Assert.That(bytes.All(b => b == 0)).IsTrue();
    }

    [Test]
    public async Task HkdfSha512_IsDeterministic()
    {
        var ikm = SecureRandom.GetBytes(32);
        var a = HkdfSha512.Derive(ikm, 32, info: "novolis"u8);
        var b = HkdfSha512.Derive(ikm, 32, info: "novolis"u8);
        await Assert.That(ConstantTime.Equals(a, b)).IsTrue();
        var other = HkdfSha512.Derive(ikm, 32, info: "other"u8);
        await Assert.That(ConstantTime.Equals(a, other)).IsFalse();
    }
}
