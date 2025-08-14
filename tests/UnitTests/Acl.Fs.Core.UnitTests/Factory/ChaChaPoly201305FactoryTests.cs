using System.Security.Cryptography;
using Acl.Fs.Core.Factory;
using Acl.Fs.Core.Resource;

namespace Acl.Fs.Core.UnitTests.Factory;

public sealed class ChaChaPoly201305FactoryTests
{
    private readonly ChaCha20Poly1305Factory _factory = new();

    [Fact]
    public void Create_ValidKey32Bytes_ReturnsAesGcmInstance()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);

        var result = _factory.Create(key);

        Assert.NotNull(result);
        Assert.IsType<ChaCha20Poly1305>(result);

        result.Dispose();
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
    public void Create_InvalidKeySize15Bytes_ThrowsCryptographicException()
    {
        var invalidKey = new byte[15];
        RandomNumberGenerator.Fill(invalidKey);

        Assert.ThrowsAny<ArgumentException>(() => _factory.Create(invalidKey));
    }
}