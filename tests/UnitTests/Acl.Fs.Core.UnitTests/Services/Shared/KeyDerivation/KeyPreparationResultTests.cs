using System.Security.Cryptography;
using Acl.Fs.Constant.Cryptography;
using Acl.Fs.Core.Abstractions.Service.Shared.KeyDerivation;
using Acl.Fs.Core.Service.Shared.KeyDerivation;

namespace Acl.Fs.Core.UnitTests.Services.Shared.KeyDerivation;

public sealed class KeyPreparationResultTests
{
    private readonly TestKeyDerivationService _testKeyDerivationService = new();
    private readonly byte[] _testPassword = "testpassword123"u8.ToArray();
    private readonly byte[] _testSalt = RandomNumberGenerator.GetBytes(CryptoConstants.Argon2IdSaltSize);

    [Fact]
    public void Constructor_WithSourceKeyOnly_Should_CreateResultWithGeneratedSalt()
    {
        using var result = new KeyPreparationResult(_testKeyDerivationService, _testPassword);

        Assert.NotNull(result);
        Assert.Equal(CryptoConstants.Argon2IdOutputKeyLength, result.DerivedKey.Length);
        Assert.Equal(_testKeyDerivationService.SaltSize, result.Salt.Length);
    }

    [Fact]
    public void Constructor_WithSourceKeyAndSalt_Should_CreateResultWithProvidedSalt()
    {
        using var result = new KeyPreparationResult(_testKeyDerivationService, _testPassword, _testSalt);

        Assert.NotNull(result);
        Assert.Equal(CryptoConstants.Argon2IdOutputKeyLength, result.DerivedKey.Length);
        Assert.Equal(_testSalt.Length, result.Salt.Length);
        Assert.True(result.Salt.SequenceEqual(_testSalt));
    }

    [Fact]
    public void DerivedKey_Should_ReturnCorrectData()
    {
        using var result = new KeyPreparationResult(_testKeyDerivationService, _testPassword, _testSalt);

        var derivedKey = result.DerivedKey;

        Assert.Equal(CryptoConstants.Argon2IdOutputKeyLength, derivedKey.Length);
        Assert.True(derivedKey.SequenceEqual(_testKeyDerivationService.LastDerivedKey));
    }

    [Fact]
    public void Salt_Should_ReturnCorrectData()
    {
        using var result = new KeyPreparationResult(_testKeyDerivationService, _testPassword, _testSalt);

        var salt = result.Salt;

        Assert.Equal(_testSalt.Length, salt.Length);
        Assert.True(salt.SequenceEqual(_testSalt));
    }

    [Fact]
    public void DerivedKey_AfterDispose_Should_ThrowObjectDisposedException()
    {
        var result = new KeyPreparationResult(_testKeyDerivationService, _testPassword, _testSalt);
        result.Dispose();

        Assert.Throws<ObjectDisposedException>(() => _ = result.DerivedKey);
    }

    [Fact]
    public void Salt_AfterDispose_Should_ThrowObjectDisposedException()
    {
        var result = new KeyPreparationResult(_testKeyDerivationService, _testPassword, _testSalt);
        result.Dispose();

        Assert.Throws<ObjectDisposedException>(() => _ = result.Salt);
    }

    [Fact]
    public void Dispose_CalledMultipleTimes_Should_NotThrow()
    {
        var result = new KeyPreparationResult(_testKeyDerivationService, _testPassword, _testSalt);

        result.Dispose();
        result.Dispose();
        result.Dispose();
    }

    [Fact]
    public void Constructor_WithEmptySourceKey_Should_CreateResult()
    {
        var emptyPassword = Array.Empty<byte>();

        using var result = new KeyPreparationResult(_testKeyDerivationService, emptyPassword, _testSalt);

        Assert.NotNull(result);
        Assert.Equal(CryptoConstants.Argon2IdOutputKeyLength, result.DerivedKey.Length);
        Assert.Equal(_testSalt.Length, result.Salt.Length);
    }

    [Fact]
    public void Constructor_WithEmptySalt_Should_CreateResult()
    {
        var emptySalt = Array.Empty<byte>();

        using var result = new KeyPreparationResult(_testKeyDerivationService, _testPassword, emptySalt);

        Assert.NotNull(result);
        Assert.Equal(CryptoConstants.Argon2IdOutputKeyLength, result.DerivedKey.Length);
        Assert.Equal(0, result.Salt.Length);
    }

    [Fact]
    public void Constructor_WithLargeSourceKey_Should_CreateResult()
    {
        var largePassword = new byte[1024];
        RandomNumberGenerator.Fill(largePassword);

        using var result = new KeyPreparationResult(_testKeyDerivationService, largePassword, _testSalt);

        Assert.NotNull(result);
        Assert.Equal(CryptoConstants.Argon2IdOutputKeyLength, result.DerivedKey.Length);
        Assert.Equal(_testSalt.Length, result.Salt.Length);
    }

    [Fact]
    public void Constructor_WithLargeSalt_Should_CreateResult()
    {
        var largeSalt = new byte[256];
        RandomNumberGenerator.Fill(largeSalt);

        using var result = new KeyPreparationResult(_testKeyDerivationService, _testPassword, largeSalt);

        Assert.NotNull(result);
        Assert.Equal(CryptoConstants.Argon2IdOutputKeyLength, result.DerivedKey.Length);
        Assert.Equal(largeSalt.Length, result.Salt.Length);
    }

    [Fact]
    public void Properties_MultipleAccess_Should_ReturnSameData()
    {
        using var result = new KeyPreparationResult(_testKeyDerivationService, _testPassword, _testSalt);

        var derivedKey1 = result.DerivedKey.ToArray();
        var derivedKey2 = result.DerivedKey.ToArray();
        var salt1 = result.Salt.ToArray();
        var salt2 = result.Salt.ToArray();

        Assert.Equal(derivedKey1, derivedKey2);
        Assert.Equal(salt1, salt2);
    }

    [Fact]
    public void Constructor_WithNullKeyDerivationService_Should_ThrowArgumentNullException()
    {
        Assert.Throws<NullReferenceException>(() =>
            new KeyPreparationResult(null!, _testPassword, _testSalt));
    }

    [Theory]
    [InlineData(8)]
    [InlineData(16)]
    [InlineData(32)]
    [InlineData(64)]
    public void Constructor_WithVariousSaltSizes_Should_CreateResult(int saltSize)
    {
        var salt = RandomNumberGenerator.GetBytes(saltSize);

        using var result = new KeyPreparationResult(_testKeyDerivationService, _testPassword, salt);

        Assert.Equal(saltSize, result.Salt.Length);
        Assert.True(result.Salt.SequenceEqual(salt));
    }

    [Fact]
    public void UsingStatement_Should_DisposeCorrectly()
    {
        KeyPreparationResult result;

        using (result = new KeyPreparationResult(_testKeyDerivationService, _testPassword, _testSalt))
        {
            _ = result.DerivedKey;
            _ = result.Salt;
        }

        Assert.Throws<ObjectDisposedException>(() => _ = result.DerivedKey);
        Assert.Throws<ObjectDisposedException>(() => _ = result.Salt);
    }

    [Fact]
    public void Constructor_WithGeneratedSalt_Should_ProduceDifferentSalts()
    {
        using var result1 = new KeyPreparationResult(_testKeyDerivationService, _testPassword);
        using var result2 = new KeyPreparationResult(_testKeyDerivationService, _testPassword);

        Assert.NotEqual(result1.Salt.ToArray(), result2.Salt.ToArray());
    }

    [Fact]
    public void Constructor_WithRealKeyDerivationService_Should_WorkCorrectly()
    {
        var realService = new Argon2KeyDerivationService();
        var password = "testpassword"u8.ToArray();
        var salt = RandomNumberGenerator.GetBytes(realService.SaltSize);

        using var result = new KeyPreparationResult(realService, password, salt);

        Assert.NotNull(result);
        Assert.Equal(CryptoConstants.Argon2IdOutputKeyLength, result.DerivedKey.Length);
        Assert.Equal(salt.Length, result.Salt.Length);
        Assert.True(result.Salt.SequenceEqual(salt));
    }

    [Fact]
    public void Properties_Should_BeConsistentAfterMultipleAccesses()
    {
        using var result = new KeyPreparationResult(_testKeyDerivationService, _testPassword, _testSalt);

        for (var i = 0; i < 10; i++)
        {
            var derivedKey = result.DerivedKey.ToArray();
            var salt = result.Salt.ToArray();

            Assert.Equal(_testKeyDerivationService.LastDerivedKey, derivedKey);
            Assert.Equal(_testSalt, salt);
        }
    }

    private sealed class TestKeyDerivationService : IKeyDerivationService
    {
        public byte[] LastDerivedKey { get; private set; } = [];
        public int SaltSize => CryptoConstants.Argon2IdSaltSize;

        public byte[] DeriveKey(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int outputLength)
        {
            var key = new byte[outputLength];
            var passwordHash = password.IsEmpty ? 42 : password[0];
            var saltHash = salt.IsEmpty ? 84 : salt[0];

            for (var i = 0; i < outputLength; i++) key[i] = (byte)((passwordHash + saltHash + i) % 256);

            LastDerivedKey = key;
            return key;
        }
    }
}