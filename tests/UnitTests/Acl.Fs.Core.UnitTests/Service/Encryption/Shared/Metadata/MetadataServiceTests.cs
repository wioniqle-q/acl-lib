using System.Buffers.Binary;
using Acl.Fs.Constant.Versioning;
using Acl.Fs.Core.Service.Encryption.Shared.Metadata;
using static Acl.Fs.Constant.Cryptography.CryptoConstants;

namespace Acl.Fs.Core.UnitTests.Service.Encryption.Shared.Metadata;

public sealed class MetadataServiceTests
{
    private readonly MetadataService _metadataService = new();

    [Fact]
    public void PrepareMetadata_ValidInputs_PrepareMetadataCorrectly()
    {
        const long originalSize = 1024L;

        var nonce = new byte[NonceSize];
        var chaCha20Salt = new byte[SaltSize];
        var argon2Salt = new byte[Argon2IdSaltSize];
        var metadataBuffer = new byte[VersionConstants.HeaderSize];
        var metadataBufferSize = VersionConstants.UnalignedHeaderSize;

        new Random(42).NextBytes(nonce);
        new Random(84).NextBytes(chaCha20Salt);
        new Random(126).NextBytes(argon2Salt);

        var originalChaCha20Salt = chaCha20Salt.ToArray();

        _metadataService.PrepareMetadata(nonce.AsSpan(), originalSize, chaCha20Salt, argon2Salt.AsSpan(),
            metadataBuffer,
            metadataBufferSize);

        Assert.Equal(VersionConstants.CurrentMajorVersion, metadataBuffer[0]);
        Assert.Equal(VersionConstants.CurrentMinorVersion, metadataBuffer[1]);

        var offset = VersionConstants.VersionHeaderSize;

        var extractedNonce = metadataBuffer.AsSpan(offset, NonceSize).ToArray();
        Assert.Equal(nonce, extractedNonce);
        offset += NonceSize;

        var extractedSize = BinaryPrimitives.ReadInt64LittleEndian(metadataBuffer.AsSpan(offset));
        Assert.Equal(originalSize, extractedSize);
        offset += sizeof(long);

        var extractedChaCha20Salt = metadataBuffer.AsSpan(offset, SaltSize).ToArray();
        Assert.NotEqual(originalChaCha20Salt, extractedChaCha20Salt);
        Assert.Equal(chaCha20Salt, extractedChaCha20Salt);
        offset += SaltSize;

        var extractedArgon2Salt = metadataBuffer.AsSpan(offset, Argon2IdSaltSize).ToArray();
        Assert.Equal(argon2Salt, extractedArgon2Salt);
    }

    [Fact]
    public void PrepareMetadata_ZeroOriginalSize_PrepareMetadataCorrectly()
    {
        const int offset = VersionConstants.VersionHeaderSize + NonceSize;
        const long originalSize = 0L;

        var nonce = new byte[NonceSize];
        var chaCha20Salt = new byte[SaltSize];
        var argon2Salt = new byte[Argon2IdSaltSize];
        var metadataBuffer = new byte[VersionConstants.HeaderSize];
        var metadataBufferSize = VersionConstants.UnalignedHeaderSize;

        new Random(42).NextBytes(nonce);
        new Random(84).NextBytes(chaCha20Salt);
        new Random(126).NextBytes(argon2Salt);

        _metadataService.PrepareMetadata(nonce.AsSpan(), originalSize, chaCha20Salt, argon2Salt.AsSpan(),
            metadataBuffer,
            metadataBufferSize);

        var extractedSize = BinaryPrimitives.ReadInt64LittleEndian(metadataBuffer.AsSpan(offset));
        Assert.Equal(0L, extractedSize);
    }

    [Fact]
    public void PrepareMetadata_LargeOriginalSize_PrepareMetadataCorrectly()
    {
        const int offset = VersionConstants.VersionHeaderSize + NonceSize;
        const long originalSize = long.MaxValue;

        var nonce = new byte[NonceSize];
        var chaCha20Salt = new byte[SaltSize];
        var argon2Salt = new byte[Argon2IdSaltSize];
        var metadataBuffer = new byte[VersionConstants.HeaderSize];
        var metadataBufferSize = VersionConstants.UnalignedHeaderSize;

        new Random(42).NextBytes(nonce);
        new Random(84).NextBytes(chaCha20Salt);
        new Random(126).NextBytes(argon2Salt);

        _metadataService.PrepareMetadata(nonce.AsSpan(), originalSize, chaCha20Salt, argon2Salt.AsSpan(),
            metadataBuffer,
            metadataBufferSize);

        var extractedSize = BinaryPrimitives.ReadInt64LittleEndian(metadataBuffer.AsSpan(offset));
        Assert.Equal(long.MaxValue, extractedSize);
    }

    [Fact]
    public void PrepareMetadata_ClearsMetadataBuffer()
    {
        const long originalSize = 1024L;

        var nonce = new byte[NonceSize];
        var chaCha20Salt = new byte[SaltSize];
        var argon2Salt = new byte[Argon2IdSaltSize];
        var metadataBuffer = new byte[VersionConstants.HeaderSize];
        var metadataBufferSize = VersionConstants.UnalignedHeaderSize;

        Array.Fill<byte>(metadataBuffer, 0xFF);

        new Random(42).NextBytes(nonce);
        new Random(84).NextBytes(chaCha20Salt);
        new Random(126).NextBytes(argon2Salt);

        _metadataService.PrepareMetadata(nonce.AsSpan(), originalSize, chaCha20Salt, argon2Salt.AsSpan(),
            metadataBuffer,
            metadataBufferSize);

        Assert.Equal(VersionConstants.CurrentMajorVersion, metadataBuffer[0]);
        Assert.Equal(VersionConstants.CurrentMinorVersion, metadataBuffer[1]);

        var unusedPortion = metadataBuffer.AsSpan(metadataBufferSize);
        foreach (var b in unusedPortion) Assert.Equal(0xFF, b);

        var actualDataEnd = VersionConstants.VersionHeaderSize + NonceSize + sizeof(long) + SaltSize + Argon2IdSaltSize;
        if (actualDataEnd >= metadataBufferSize) return;

        var clearedPortion = metadataBuffer.AsSpan(actualDataEnd, metadataBufferSize - actualDataEnd);
        foreach (var b in clearedPortion) Assert.Equal(0, b);
    }

    [Fact]
    public void PrepareMetadata_SameInputs_ProducesSameOutput()
    {
        const long originalSize = 1024L;

        var nonce = new byte[NonceSize];
        var chaCha20Salt = new byte[SaltSize];
        var argon2Salt = new byte[Argon2IdSaltSize];

        for (var i = 0; i < nonce.Length; i++) nonce[i] = (byte)(i % 256);
        for (var i = 0; i < chaCha20Salt.Length; i++) chaCha20Salt[i] = (byte)((i + 50) % 256);
        for (var i = 0; i < argon2Salt.Length; i++) argon2Salt[i] = (byte)((i + 100) % 256);

        var metadataBuffer1 = new byte[VersionConstants.HeaderSize];
        var metadataBuffer2 = new byte[VersionConstants.HeaderSize];
        var metadataBufferSize = VersionConstants.UnalignedHeaderSize;

        _metadataService.PrepareMetadata(nonce.AsSpan(), originalSize, chaCha20Salt, argon2Salt.AsSpan(),
            metadataBuffer1,
            metadataBufferSize);
        _metadataService.PrepareMetadata(nonce.AsSpan(), originalSize, chaCha20Salt, argon2Salt.AsSpan(),
            metadataBuffer2,
            metadataBufferSize);

        Assert.Equal(metadataBuffer1.AsSpan(0, metadataBufferSize).ToArray(),
            metadataBuffer2.AsSpan(0, metadataBufferSize).ToArray());
    }

    [Fact]
    public void PrepareMetadata_DifferentNonces_ProducesDifferentSalts()
    {
        const int offset = VersionConstants.VersionHeaderSize + NonceSize + sizeof(long);
        const long originalSize = 1024L;

        var nonce1 = new byte[NonceSize];
        var nonce2 = new byte[NonceSize];
        var chaCha20Salt = new byte[SaltSize];
        var argon2Salt = new byte[Argon2IdSaltSize];

        new Random(42).NextBytes(nonce1);
        new Random(84).NextBytes(nonce2);
        new Random(126).NextBytes(chaCha20Salt);
        new Random(168).NextBytes(argon2Salt);

        var metadataBuffer1 = new byte[VersionConstants.HeaderSize];
        var metadataBuffer2 = new byte[VersionConstants.HeaderSize];
        var metadataBufferSize = VersionConstants.UnalignedHeaderSize;

        _metadataService.PrepareMetadata(nonce1.AsSpan(), originalSize, chaCha20Salt, argon2Salt.AsSpan(),
            metadataBuffer1,
            metadataBufferSize);
        _metadataService.PrepareMetadata(nonce2.AsSpan(), originalSize, chaCha20Salt, argon2Salt.AsSpan(),
            metadataBuffer2,
            metadataBufferSize);

        var salt1 = metadataBuffer1.AsSpan(offset, SaltSize).ToArray();
        var salt2 = metadataBuffer2.AsSpan(offset, SaltSize).ToArray();
        Assert.NotEqual(salt1, salt2);
    }

    [Fact]
    public async Task WriteHeaderAsync_ValidInputs_WritesHeaderCorrectly()
    {
        using var memoryStream = new MemoryStream();
        var metadataBuffer = new byte[VersionConstants.HeaderSize];
        var metadataBufferSize = VersionConstants.UnalignedHeaderSize;

        new Random(42).NextBytes(metadataBuffer.AsSpan(0, metadataBufferSize));

        await _metadataService.WriteHeaderAsync(memoryStream, metadataBuffer, metadataBufferSize,
            CancellationToken.None);

        Assert.Equal(metadataBufferSize, memoryStream.Length);

        var writtenData = memoryStream.ToArray();
        Assert.Equal(metadataBuffer.AsSpan(0, metadataBufferSize).ToArray(), writtenData);
    }

    [Fact]
    public async Task WriteHeaderAsync_EmptyBuffer_WritesNothing()
    {
        using var memoryStream = new MemoryStream();
        var metadataBuffer = new byte[VersionConstants.HeaderSize];
        const int metadataBufferSize = 0;

        await _metadataService.WriteHeaderAsync(memoryStream, metadataBuffer, metadataBufferSize,
            CancellationToken.None);

        Assert.Equal(0, memoryStream.Length);
    }

    [Fact]
    public async Task WriteHeaderAsync_CancelledToken_ThrowsOperationCancelledException()
    {
        using var memoryStream = new MemoryStream();
        var metadataBuffer = new byte[VersionConstants.HeaderSize];
        var metadataBufferSize = VersionConstants.UnalignedHeaderSize;

        var cancellationTokenSource = new CancellationTokenSource();
        await cancellationTokenSource.CancelAsync();

        await Assert.ThrowsAsync<OperationCanceledException>(async () =>
            await _metadataService.WriteHeaderAsync(memoryStream, metadataBuffer, metadataBufferSize,
                cancellationTokenSource.Token));
    }

    [Fact]
    public async Task WriteHeaderAsync_StreamDisposed_ThrowsObjectDisposedException()
    {
        var memoryStream = new MemoryStream();
        var metadataBuffer = new byte[VersionConstants.HeaderSize];
        var metadataBufferSize = VersionConstants.UnalignedHeaderSize;

        await memoryStream.DisposeAsync();

        await Assert.ThrowsAsync<ObjectDisposedException>(async () =>
            await _metadataService.WriteHeaderAsync(memoryStream, metadataBuffer, metadataBufferSize,
                CancellationToken.None));
    }

    [Fact]
    public async Task WriteHeaderAsync_ReadOnlyStream_ThrowsNotSupportedException()
    {
        var readOnlyBuffer = new byte[100];
        new Random(42).NextBytes(readOnlyBuffer);

        using var readOnlyStream = new MemoryStream(readOnlyBuffer, false);
        var metadataBuffer = new byte[VersionConstants.HeaderSize];
        var metadataBufferSize = VersionConstants.UnalignedHeaderSize;

        await Assert.ThrowsAsync<NotSupportedException>(async () =>
            await _metadataService.WriteHeaderAsync(readOnlyStream, metadataBuffer, metadataBufferSize,
                CancellationToken.None));
    }

    [Fact]
    public async Task WriteHeaderAsync_MultipleWrites_AppendsCorrectly()
    {
        using var memoryStream = new MemoryStream();
        var metadataBuffer1 = new byte[VersionConstants.HeaderSize];
        var metadataBuffer2 = new byte[VersionConstants.HeaderSize];
        var metadataBufferSize = VersionConstants.UnalignedHeaderSize;

        new Random(42).NextBytes(metadataBuffer1.AsSpan(0, metadataBufferSize));
        new Random(84).NextBytes(metadataBuffer2.AsSpan(0, metadataBufferSize));

        await _metadataService.WriteHeaderAsync(memoryStream, metadataBuffer1, metadataBufferSize,
            CancellationToken.None);
        await _metadataService.WriteHeaderAsync(memoryStream, metadataBuffer2, metadataBufferSize,
            CancellationToken.None);

        Assert.Equal(metadataBufferSize * 2, memoryStream.Length);

        var writtenData = memoryStream.ToArray();
        Assert.Equal(metadataBuffer1.AsSpan(0, metadataBufferSize).ToArray(),
            writtenData.AsSpan(0, metadataBufferSize).ToArray());
        Assert.Equal(metadataBuffer2.AsSpan(0, metadataBufferSize).ToArray(),
            writtenData.AsSpan(metadataBufferSize, metadataBufferSize).ToArray());
    }

    [Theory]
    [InlineData(1)]
    [InlineData(16)]
    [InlineData(24)]
    [InlineData(32)]
    public void PrepareMetadata_VariousNonceSizes_HandlesCorrectly(int nonceSize)
    {
        const int offset = VersionConstants.VersionHeaderSize;
        const long originalSize = 1024L;

        var nonce = new byte[nonceSize];
        var chaCha20Salt = new byte[SaltSize];
        var argon2Salt = new byte[Argon2IdSaltSize];
        var expectedBufferSize =
            VersionConstants.VersionHeaderSize + nonceSize + sizeof(long) + SaltSize + Argon2IdSaltSize;
        var metadataBuffer = new byte[expectedBufferSize + 100];

        new Random(42).NextBytes(nonce);
        new Random(84).NextBytes(chaCha20Salt);
        new Random(126).NextBytes(argon2Salt);

        _metadataService.PrepareMetadata(nonce.AsSpan(), originalSize, chaCha20Salt, argon2Salt.AsSpan(),
            metadataBuffer,
            expectedBufferSize, nonceSize);

        var extractedNonce = metadataBuffer.AsSpan(offset, nonceSize).ToArray();
        Assert.Equal(nonce, extractedNonce);
    }

    [Fact]
    public void PrepareMetadata_NegativeOriginalSize_PrepareMetadataCorrectly()
    {
        const int offset = VersionConstants.VersionHeaderSize + NonceSize;
        const long originalSize = -1L;

        var nonce = new byte[NonceSize];
        var chaCha20Salt = new byte[SaltSize];
        var argon2Salt = new byte[Argon2IdSaltSize];
        var metadataBuffer = new byte[VersionConstants.HeaderSize];
        var metadataBufferSize = VersionConstants.UnalignedHeaderSize;

        new Random(42).NextBytes(nonce);
        new Random(84).NextBytes(chaCha20Salt);
        new Random(126).NextBytes(argon2Salt);

        _metadataService.PrepareMetadata(nonce.AsSpan(), originalSize, chaCha20Salt, argon2Salt.AsSpan(),
            metadataBuffer,
            metadataBufferSize);

        var extractedSize = BinaryPrimitives.ReadInt64LittleEndian(metadataBuffer.AsSpan(offset));
        Assert.Equal(-1L, extractedSize);
    }
}