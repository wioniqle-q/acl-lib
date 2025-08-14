using System.Security.Cryptography;
using Acl.Fs.Core.Factory;
using Acl.Fs.Core.Resource;
using NSec.Cryptography;

namespace Acl.Fs.Core.UnitTests.Factory;

public sealed class XChaCha20Poly1305FactoryTests
{
    private readonly XChaCha20Poly1305Factory _factory = new();

    [Fact]
    public void Create_ValidKey32Bytes_ReturnsXChaCha20Poly1305Instance()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);

        var result = _factory.Create(key);

        Assert.NotNull(result);
        Assert.IsType<XChaCha20Poly1305>(result);
    }

    [Fact]
    public void Create_NullKey_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentException>(() => _factory.Create(null!));
    }

    [Fact]
    public void Create_EmptyKey_ThrowsArgumentException()
    {
        var emptyKey = Array.Empty<byte>();

        var exception = Assert.Throws<ArgumentException>(() => _factory.Create(emptyKey));
        Assert.Contains(ErrorMessages.InvalidKeySize, exception.Message);
    }

    [Fact]
    public void Create_InvalidKeySize15Bytes_ThrowsArgumentException()
    {
        var invalidKey = new byte[15];
        RandomNumberGenerator.Fill(invalidKey);

        var exception = Assert.Throws<ArgumentException>(() => _factory.Create(invalidKey));
        Assert.Contains(ErrorMessages.InvalidKeySize, exception.Message);
    }

    [Fact]
    public void Create_InvalidKeySize16Bytes_ThrowsArgumentException()
    {
        var invalidKey = new byte[16];
        RandomNumberGenerator.Fill(invalidKey);

        var exception = Assert.Throws<ArgumentException>(() => _factory.Create(invalidKey));
        Assert.Contains(ErrorMessages.InvalidKeySize, exception.Message);
    }

    [Fact]
    public void Create_InvalidKeySize64Bytes_ThrowsArgumentException()
    {
        var invalidKey = new byte[64];
        RandomNumberGenerator.Fill(invalidKey);

        var exception = Assert.Throws<ArgumentException>(() => _factory.Create(invalidKey));
        Assert.Contains(ErrorMessages.InvalidKeySize, exception.Message);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(8)]
    [InlineData(16)]
    [InlineData(24)]
    [InlineData(31)]
    [InlineData(33)]
    [InlineData(48)]
    [InlineData(128)]
    public void Create_WithInvalidKeySizes_ThrowsArgumentException(int keySize)
    {
        var invalidKey = new byte[keySize];
        RandomNumberGenerator.Fill(invalidKey);

        var exception = Assert.Throws<ArgumentException>(() => _factory.Create(invalidKey));
        Assert.Contains(ErrorMessages.InvalidKeySize, exception.Message);
        Assert.Equal("key", exception.ParamName);
    }
}