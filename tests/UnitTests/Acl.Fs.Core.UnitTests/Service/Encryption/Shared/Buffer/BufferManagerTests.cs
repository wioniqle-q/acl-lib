using Acl.Fs.Core.Abstractions.Service.Encryption.Shared.Buffer;
using Acl.Fs.Core.Service.Encryption.Shared.Buffer;
using static Acl.Fs.Constant.Cryptography.CryptoConstants;
using static Acl.Fs.Constant.Storage.StorageConstants;

namespace Acl.Fs.Core.UnitTests.Service.Encryption.Shared.Buffer;

public sealed class BufferManagerTests
{
    [Fact]
    public void Constructor_ShouldInitializeAllBuffersWithCorrectSizes()
    {
        const int metadataBufferSize = 1024;

        using var bufferManager = new BufferManager(metadataBufferSize, NonceSize);

        Assert.NotNull(bufferManager.Buffer);
        Assert.True(bufferManager.Buffer.Length >= BufferSize);

        Assert.NotNull(bufferManager.Ciphertext);
        Assert.True(bufferManager.Ciphertext.Length >= BufferSize);

        Assert.NotNull(bufferManager.MetadataBuffer);
        Assert.True(bufferManager.MetadataBuffer.Length >= metadataBufferSize);

        Assert.NotNull(bufferManager.Tag);
        Assert.True(bufferManager.Tag.Length >= TagSize);

        Assert.NotNull(bufferManager.ChunkNonce);
        Assert.True(bufferManager.ChunkNonce.Length >= NonceSize);

        Assert.NotNull(bufferManager.Salt);
        Assert.True(bufferManager.Salt.Length >= SaltSize);
    }

    [Theory]
    [InlineData(256)]
    [InlineData(512)]
    [InlineData(1024)]
    [InlineData(2048)]
    public void Constructor_WithDifferentMetadataBufferSizes_ShouldCreateCorrectSizedMetadataBuffer(
        int metadataBufferSize)
    {
        using var bufferManager = new BufferManager(metadataBufferSize, NonceSize);

        Assert.True(bufferManager.MetadataBuffer.Length >= metadataBufferSize);
    }

    [Fact]
    public void Constructor_WithZeroMetadataBufferSize_ShouldCreateEmptyMetadataBuffer()
    {
        using var bufferManager = new BufferManager(0, NonceSize);

        Assert.Empty(bufferManager.MetadataBuffer);
    }

    [Fact]
    public void Buffer_ShouldBeInitializedWithCryptoPoolData()
    {
        const int metadataBufferSize = 1024;

        using var bufferManager = new BufferManager(metadataBufferSize, NonceSize);

        Assert.NotNull(bufferManager.Buffer);
        Assert.True(bufferManager.Buffer.Length >= BufferSize);
    }

    [Fact]
    public void Ciphertext_ShouldBeInitializedWithCryptoPoolData()
    {
        const int metadataBufferSize = 1024;

        using var bufferManager = new BufferManager(metadataBufferSize, NonceSize);

        Assert.NotNull(bufferManager.Ciphertext);
        Assert.True(bufferManager.Ciphertext.Length >= BufferSize);
    }

    [Fact]
    public void MetadataBuffer_ShouldBeInitializedWithCryptoPoolData()
    {
        const int metadataBufferSize = 1024;

        using var bufferManager = new BufferManager(metadataBufferSize, NonceSize);

        Assert.NotNull(bufferManager.MetadataBuffer);
        Assert.True(bufferManager.MetadataBuffer.Length >= metadataBufferSize);
    }

    [Fact]
    public void Tag_ShouldBeInitializedWithCryptoPoolData()
    {
        const int metadataBufferSize = 1024;

        using var bufferManager = new BufferManager(metadataBufferSize, NonceSize);

        Assert.NotNull(bufferManager.Tag);
        Assert.True(bufferManager.Tag.Length >= TagSize);
    }

    [Fact]
    public void ChunkNonce_ShouldBeInitializedWithCryptoPoolData()
    {
        const int metadataBufferSize = 1024;

        using var bufferManager = new BufferManager(metadataBufferSize, NonceSize);

        Assert.NotNull(bufferManager.ChunkNonce);
        Assert.True(bufferManager.ChunkNonce.Length >= NonceSize);
    }

    [Fact]
    public void Salt_ShouldBeInitializedWithCryptoPoolData()
    {
        const int metadataBufferSize = 1024;

        using var bufferManager = new BufferManager(metadataBufferSize, NonceSize);

        Assert.NotNull(bufferManager.Salt);
        Assert.True(bufferManager.Salt.Length >= SaltSize);
    }

    [Fact]
    public void Dispose_ShouldCompleteWithoutExceptions()
    {
        const int metadataBufferSize = 1024;
        var bufferManager = new BufferManager(metadataBufferSize, NonceSize);

        var exception = Record.Exception(() => bufferManager.Dispose());
        Assert.Null(exception);
    }

    [Fact]
    public void Dispose_CalledMultipleTimes_ShouldNotThrow()
    {
        const int metadataBufferSize = 1024;
        var bufferManager = new BufferManager(metadataBufferSize, NonceSize);

        var exception = Record.Exception(() =>
        {
            bufferManager.Dispose();
            bufferManager.Dispose();
            bufferManager.Dispose();
        });
        Assert.Null(exception);
    }

    [Fact]
    public void BufferManager_ShouldImplementIBufferManager()
    {
        const int metadataBufferSize = 1024;

        using var bufferManager = new BufferManager(metadataBufferSize, NonceSize);

        Assert.IsType<IBufferManager>(bufferManager,
            false);
    }

    [Fact]
    public void UsingStatement_ShouldAutomaticallyCallDispose()
    {
        const int metadataBufferSize = 1024;
        BufferManager bufferManager;

        var exception = Record.Exception(() =>
        {
            using (bufferManager = new BufferManager(metadataBufferSize, NonceSize))
            {
                _ = bufferManager.Buffer;
            }
        });

        Assert.Null(exception);
    }

    [Fact]
    public void BufferProperties_ShouldReturnSameInstanceOnMultipleCalls()
    {
        const int metadataBufferSize = 1024;

        using var bufferManager = new BufferManager(metadataBufferSize, NonceSize);

        Assert.Same(bufferManager.Buffer, bufferManager.Buffer);
        Assert.Same(bufferManager.Ciphertext, bufferManager.Ciphertext);
        Assert.Same(bufferManager.MetadataBuffer, bufferManager.MetadataBuffer);
        Assert.Same(bufferManager.Tag, bufferManager.Tag);
        Assert.Same(bufferManager.ChunkNonce, bufferManager.ChunkNonce);
        Assert.Same(bufferManager.Salt, bufferManager.Salt);
    }
}