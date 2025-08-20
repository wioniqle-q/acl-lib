using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Acl.Fs.Audit.Abstractions;
using Acl.Fs.Constant.Cryptography;
using Acl.Fs.Core.Abstractions.Service.Shared.KeyDerivation;
using Acl.Fs.Core.Service.Shared.KeyDerivation;

namespace Acl.Fs.Core.UnitTests.Service.Shared.KeyDerivation;

public sealed class KeyPreparationServiceTests
{
    private readonly KeyPreparationService _keyPreparationService;
    private readonly TestAuditLogger _testAuditLogger = new();
    private readonly TestKeyDerivationService _testKeyDerivationService = new();
    private readonly byte[] _testPassword = "testpassword123"u8.ToArray();
    private readonly byte[] _testSalt = RandomNumberGenerator.GetBytes(CryptoConstants.Argon2IdSaltSize);

    public KeyPreparationServiceTests()
    {
        _keyPreparationService = new KeyPreparationService(_testKeyDerivationService, _testAuditLogger);
    }

    [Fact]
    public void PrepareKey_WithPasswordOnly_Should_CreateResultWithGeneratedSalt()
    {
        using var result = _keyPreparationService.PrepareKey(_testPassword);

        Assert.NotNull(result);
        Assert.Equal(CryptoConstants.Argon2IdOutputKeyLength, result.DerivedKey.Length);
        Assert.Equal(_testKeyDerivationService.SaltSize, result.Salt.Length);
    }

    [Fact]
    public void PrepareKeyWithSalt_WithPasswordAndSalt_Should_CreateResultWithProvidedSalt()
    {
        using var result = _keyPreparationService.PrepareKeyWithSalt(_testPassword, _testSalt);

        Assert.NotNull(result);
        Assert.Equal(CryptoConstants.Argon2IdOutputKeyLength, result.DerivedKey.Length);
        Assert.Equal(_testSalt.Length, result.Salt.Length);
        Assert.True(result.Salt.SequenceEqual(_testSalt));
    }

    [Fact]
    public void PrepareKeyWithSalt_WithAuditLogger_Should_CreateResultAndLogMemoryOperations()
    {
        using var result = _keyPreparationService.PrepareKeyWithSalt(_testPassword, _testSalt);

        Assert.NotNull(result);
        Assert.Equal(CryptoConstants.Argon2IdOutputKeyLength, result.DerivedKey.Length);
        Assert.True(_testAuditLogger.LoggedEvents.Count > 0);
    }

    [Fact]
    public void DerivedKey_Should_ReturnCorrectData()
    {
        using var result = _keyPreparationService.PrepareKeyWithSalt(_testPassword, _testSalt);

        var derivedKey = result.DerivedKey;

        Assert.Equal(CryptoConstants.Argon2IdOutputKeyLength, derivedKey.Length);
        Assert.True(derivedKey.SequenceEqual(_testKeyDerivationService.LastDerivedKey));
    }

    [Fact]
    public void Salt_Should_ReturnCorrectData()
    {
        using var result = _keyPreparationService.PrepareKeyWithSalt(_testPassword, _testSalt);

        var salt = result.Salt;

        Assert.Equal(_testSalt.Length, salt.Length);
        Assert.True(salt.SequenceEqual(_testSalt));
    }

    [Fact]
    public void DerivedKey_AfterDispose_Should_ThrowObjectDisposedException()
    {
        var result = _keyPreparationService.PrepareKeyWithSalt(_testPassword, _testSalt);
        result.Dispose();

        Assert.Throws<ObjectDisposedException>(() => _ = result.DerivedKey);
    }

    [Fact]
    public void Salt_AfterDispose_Should_ThrowObjectDisposedException()
    {
        var result = _keyPreparationService.PrepareKeyWithSalt(_testPassword, _testSalt);
        result.Dispose();

        Assert.Throws<ObjectDisposedException>(() => _ = result.Salt);
    }

    [Fact]
    public void Dispose_CalledMultipleTimes_Should_NotThrow()
    {
        var result = _keyPreparationService.PrepareKeyWithSalt(_testPassword, _testSalt);

        result.Dispose();
        result.Dispose();
        result.Dispose();
    }

    [Fact]
    public void PrepareKeyWithSalt_WithEmptyPassword_Should_CreateResult()
    {
        var emptyPassword = Array.Empty<byte>();

        using var result = _keyPreparationService.PrepareKeyWithSalt(emptyPassword, _testSalt);

        Assert.NotNull(result);
        Assert.Equal(CryptoConstants.Argon2IdOutputKeyLength, result.DerivedKey.Length);
        Assert.Equal(_testSalt.Length, result.Salt.Length);
    }

    [Fact]
    public void PrepareKeyWithSalt_WithEmptySalt_Should_CreateResult()
    {
        var emptySalt = Array.Empty<byte>();

        using var result = _keyPreparationService.PrepareKeyWithSalt(_testPassword, emptySalt);

        Assert.NotNull(result);
        Assert.Equal(CryptoConstants.Argon2IdOutputKeyLength, result.DerivedKey.Length);
        Assert.Equal(0, result.Salt.Length);
    }

    [Fact]
    public void PrepareKeyWithSalt_WithLargePassword_Should_CreateResult()
    {
        var largePassword = new byte[1024];
        RandomNumberGenerator.Fill(largePassword);

        using var result = _keyPreparationService.PrepareKeyWithSalt(largePassword, _testSalt);

        Assert.NotNull(result);
        Assert.Equal(CryptoConstants.Argon2IdOutputKeyLength, result.DerivedKey.Length);
        Assert.Equal(_testSalt.Length, result.Salt.Length);
    }

    [Fact]
    public void PrepareKeyWithSalt_WithLargeSalt_Should_CreateResult()
    {
        var largeSalt = new byte[256];
        RandomNumberGenerator.Fill(largeSalt);

        using var result = _keyPreparationService.PrepareKeyWithSalt(_testPassword, largeSalt);

        Assert.NotNull(result);
        Assert.Equal(CryptoConstants.Argon2IdOutputKeyLength, result.DerivedKey.Length);
        Assert.Equal(largeSalt.Length, result.Salt.Length);
    }

    [Fact]
    public void Properties_MultipleAccess_Should_ReturnSameData()
    {
        using var result = _keyPreparationService.PrepareKeyWithSalt(_testPassword, _testSalt);

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
        Assert.Throws<ArgumentNullException>(() =>
            new KeyPreparationService(null!, _testAuditLogger));
    }

    [Theory]
    [InlineData(8)]
    [InlineData(16)]
    [InlineData(32)]
    [InlineData(64)]
    public void PrepareKeyWithSalt_WithVariousSaltSizes_Should_CreateResult(int saltSize)
    {
        var salt = RandomNumberGenerator.GetBytes(saltSize);

        using var result = _keyPreparationService.PrepareKeyWithSalt(_testPassword, salt);

        Assert.Equal(saltSize, result.Salt.Length);
        Assert.True(result.Salt.SequenceEqual(salt));
    }

    [Fact]
    public void UsingStatement_Should_DisposeCorrectly()
    {
        IKeyPreparationResult result;

        using (result = _keyPreparationService.PrepareKeyWithSalt(_testPassword, _testSalt))
        {
            _ = result.DerivedKey;
            _ = result.Salt;
        }

        Assert.Throws<ObjectDisposedException>(() => _ = result.DerivedKey);
        Assert.Throws<ObjectDisposedException>(() => _ = result.Salt);
    }

    [Fact]
    public void PrepareKey_WithGeneratedSalt_Should_ProduceDifferentSalts()
    {
        using var result1 = _keyPreparationService.PrepareKey(_testPassword);
        using var result2 = _keyPreparationService.PrepareKey(_testPassword);

        Assert.NotEqual(result1.Salt.ToArray(), result2.Salt.ToArray());
    }

    [Fact]
    public void PrepareKeyWithSalt_WithRealKeyDerivationService_Should_WorkCorrectly()
    {
        var realService = new Argon2KeyDerivationService();
        var realPreparationService = new KeyPreparationService(realService, _testAuditLogger);
        var password = "testpassword"u8.ToArray();
        var salt = RandomNumberGenerator.GetBytes(realService.SaltSize);

        using var result = realPreparationService.PrepareKeyWithSalt(password, salt);

        Assert.NotNull(result);
        Assert.Equal(CryptoConstants.Argon2IdOutputKeyLength, result.DerivedKey.Length);
        Assert.Equal(salt.Length, result.Salt.Length);
        Assert.True(result.Salt.SequenceEqual(salt));
    }

    [Fact]
    public void Properties_Should_BeConsistentAfterMultipleAccesses()
    {
        using var result = _keyPreparationService.PrepareKeyWithSalt(_testPassword, _testSalt);

        for (var i = 0; i < 10; i++)
        {
            var derivedKey = result.DerivedKey.ToArray();
            var salt = result.Salt.ToArray();

            Assert.Equal(_testKeyDerivationService.LastDerivedKey, derivedKey);
            Assert.Equal(_testSalt, salt);
        }
    }

    [Fact]
    public void PrepareKeyWithSalt_WithMemoryLocking_ShouldNotThrow()
    {
        using var result = _keyPreparationService.PrepareKeyWithSalt(_testPassword, _testSalt);

        Assert.NotNull(result);
        Assert.Equal(CryptoConstants.Argon2IdOutputKeyLength, result.DerivedKey.Length);
    }

    [Fact]
    public void Dispose_WithMemoryLocking_ShouldCleanupSafely()
    {
        var result = _keyPreparationService.PrepareKeyWithSalt(_testPassword, _testSalt);

        result.Dispose();
        result.Dispose();
        result.Dispose();
    }

    [Fact]
    public void MultipleInstances_ShouldHandleMemoryLockingIndependently()
    {
        using var result1 = _keyPreparationService.PrepareKey(_testPassword);
        using var result2 = _keyPreparationService.PrepareKeyWithSalt(_testPassword, _testSalt);
        using var result3 = _keyPreparationService.PrepareKey(_testPassword);

        Assert.NotNull(result1);
        Assert.NotNull(result2);
        Assert.NotNull(result3);

        _ = result1.DerivedKey;
        _ = result2.DerivedKey;
        _ = result3.DerivedKey;
    }

    [Fact]
    public void PrepareKeyWithSalt_WithLargeKey_ShouldHandleMemoryLockingCorrectly()
    {
        var largePassword = new byte[4096];
        RandomNumberGenerator.Fill(largePassword);

        using var result = _keyPreparationService.PrepareKeyWithSalt(largePassword, _testSalt);

        Assert.NotNull(result);
        Assert.Equal(CryptoConstants.Argon2IdOutputKeyLength, result.DerivedKey.Length);
    }

    [Fact]
    public void PrepareKeyWithSalt_ExceptionDuringConstruction_ShouldCleanupMemoryProperly()
    {
        var faultyService = new FaultyKeyDerivationService();
        var faultyPreparationService = new KeyPreparationService(faultyService, _testAuditLogger);

        Assert.Throws<InvalidOperationException>(() =>
            faultyPreparationService.PrepareKeyWithSalt(_testPassword, _testSalt));
    }

    [Fact]
    public void DerivedKey_AccessAfterCreation_ShouldWorkWithMemoryLocking()
    {
        using var result = _keyPreparationService.PrepareKeyWithSalt(_testPassword, _testSalt);

        var key1 = result.DerivedKey.ToArray();
        var key2 = result.DerivedKey.ToArray();
        var key3 = result.DerivedKey.ToArray();

        Assert.Equal(key1, key2);
        Assert.Equal(key2, key3);
    }

    [SkippableFact]
    public void PrepareKeyWithSalt_OnWindows_ShouldAttemptMemoryLocking()
    {
        Skip.IfNot(RuntimeInformation.IsOSPlatform(OSPlatform.Windows), "This test is Windows-specific");

        using var result = _keyPreparationService.PrepareKeyWithSalt(_testPassword, _testSalt);

        Assert.NotNull(result);
    }

    [SkippableFact]
    public void PrepareKeyWithSalt_OnNonWindows_ShouldSkipMemoryLocking()
    {
        Skip.If(RuntimeInformation.IsOSPlatform(OSPlatform.Windows), "This test is for non-Windows platforms");

        using var result = _keyPreparationService.PrepareKeyWithSalt(_testPassword, _testSalt);

        Assert.NotNull(result);
        Assert.Equal(CryptoConstants.Argon2IdOutputKeyLength, result.DerivedKey.Length);
    }

    [Fact]
    public async Task Dispose_ConcurrentAccess_ShouldBeSafe()
    {
        var result = _keyPreparationService.PrepareKeyWithSalt(_testPassword, _testSalt);

        var tasks = new List<Task>();
        for (var i = 0; i < 10; i++) tasks.Add(Task.Run(() => result.Dispose()));

        await Task.WhenAll(tasks);

        Assert.Throws<ObjectDisposedException>(() => _ = result.DerivedKey);
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

    private sealed class FaultyKeyDerivationService : IKeyDerivationService
    {
        public int SaltSize => CryptoConstants.Argon2IdSaltSize;

        public byte[] DeriveKey(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int outputLength)
        {
            throw new InvalidOperationException("Simulated key derivation failure");
        }
    }

    private sealed class TestAuditLogger : IAuditLogger
    {
        public List<string> LoggedEvents { get; } = [];

        public ValueTask LogAsync(IAuditEntry entry, CancellationToken cancellationToken = default)
        {
            LoggedEvents.Add($"[{entry.Category}] {entry.Message} (EventId: {entry.EventId})");
            return ValueTask.CompletedTask;
        }
    }
}