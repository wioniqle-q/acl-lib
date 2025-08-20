using Acl.Fs.Core.Abstractions.Service.Decryption.Shared.Buffer;
using Acl.Fs.Core.Service.Decryption.Shared.Buffer;
using static Acl.Fs.Constant.Cryptography.CryptoConstants;
using static Acl.Fs.Constant.Storage.StorageConstants;

namespace Acl.Fs.Core.UnitTests.Service.Decryption.Shared.Buffer;

public sealed class BufferManagerTests
{
    [Fact]
    public void Constructor_ShouldInitializeAllBuffersWithCorrectSizes()
    {
        const int metadataBufferSize = 1024;
        const int nonceSize = NonceSize;

        using var bufferManager = new BufferManager(metadataBufferSize, nonceSize);

        Assert.NotNull(bufferManager.Buffer);
        Assert.True(bufferManager.Buffer.Length >= BufferSize);

        Assert.NotNull(bufferManager.Plaintext);
        Assert.True(bufferManager.Plaintext.Length >= BufferSize);

        Assert.NotNull(bufferManager.AlignedBuffer);
        Assert.True(bufferManager.AlignedBuffer.Length >= BufferSize);

        Assert.NotNull(bufferManager.MetadataBuffer);
        Assert.True(bufferManager.MetadataBuffer.Length >= metadataBufferSize);

        Assert.NotNull(bufferManager.Tag);
        Assert.True(bufferManager.Tag.Length >= TagSize);

        Assert.NotNull(bufferManager.ChunkNonce);
        Assert.True(bufferManager.ChunkNonce.Length >= nonceSize);

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
    public void Plaintext_ShouldBeInitializedWithCryptoPoolData()
    {
        const int metadataBufferSize = 1024;

        using var bufferManager = new BufferManager(metadataBufferSize, NonceSize);

        Assert.NotNull(bufferManager.Plaintext);
        Assert.True(bufferManager.Plaintext.Length >= BufferSize);
    }

    [Fact]
    public void AlignedBuffer_ShouldBeInitializedWithCryptoPoolData()
    {
        const int metadataBufferSize = 1024;

        using var bufferManager = new BufferManager(metadataBufferSize, NonceSize);

        Assert.NotNull(bufferManager.AlignedBuffer);
        Assert.True(bufferManager.AlignedBuffer.Length >= BufferSize);
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

        Assert.IsType<IBufferManager>(bufferManager, false);
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
        Assert.Same(bufferManager.Plaintext, bufferManager.Plaintext);
        Assert.Same(bufferManager.AlignedBuffer, bufferManager.AlignedBuffer);
        Assert.Same(bufferManager.MetadataBuffer, bufferManager.MetadataBuffer);
        Assert.Same(bufferManager.Tag, bufferManager.Tag);
        Assert.Same(bufferManager.ChunkNonce, bufferManager.ChunkNonce);
        Assert.Same(bufferManager.Salt, bufferManager.Salt);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(10)]
    [InlineData(100)]
    [InlineData(1000)]
    public void Constructor_WithVariousValidSizes_ShouldSucceed(int metadataBufferSize)
    {
        using var bufferManager = new BufferManager(metadataBufferSize, NonceSize);

        Assert.NotNull(bufferManager);
        Assert.True(bufferManager.MetadataBuffer.Length >= metadataBufferSize);
    }

    [Fact]
    public void DecryptionBufferManager_ShouldHavePlaintextAndAlignedBuffer()
    {
        const int metadataBufferSize = 1024;

        using var bufferManager = new BufferManager(metadataBufferSize, NonceSize);

        Assert.NotNull(bufferManager.Plaintext);
        Assert.NotNull(bufferManager.AlignedBuffer);

        Assert.True(bufferManager.Plaintext.Length >= BufferSize);
        Assert.True(bufferManager.AlignedBuffer.Length >= BufferSize);
    }
}