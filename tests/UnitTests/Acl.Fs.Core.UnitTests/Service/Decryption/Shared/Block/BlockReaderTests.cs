using Acl.Fs.Constant.Cryptography;
using Acl.Fs.Constant.Storage;
using Acl.Fs.Core.Service.Decryption.Shared.Block;

namespace Acl.Fs.Core.UnitTests.Service.Decryption.Shared.Block;

public sealed class BlockReaderTests
{
    [Fact]
    public async Task ReadTagAsync_SectorAligned_ReadsCorrectly()
    {
        var data = new byte[StorageConstants.SectorSize];
        for (var i = 0; i < data.Length; i++)
            data[i] = (byte)i;

        var stream = new MemoryStream(data);
        var reader = new BlockReader();
        var metadataBuffer = new byte[StorageConstants.SectorSize];
        var tag = new byte[CryptoConstants.TagSize];

        await reader.ReadTagAsync(stream, true, tag, metadataBuffer);

        Assert.Equal(data, metadataBuffer);
        Assert.Equal(data.Take(CryptoConstants.TagSize).ToArray(), tag);
    }

    [Fact]
    public async Task ReadTagAsync_NonSectorAligned_ReadsCorrectly()
    {
        var data = new byte[CryptoConstants.TagSize];
        for (var i = 0; i < data.Length; i++)
            data[i] = (byte)i;

        var stream = new MemoryStream(data);
        var reader = new BlockReader();
        var tag = new byte[CryptoConstants.TagSize];

        await reader.ReadTagAsync(stream, false, tag, []);

        Assert.Equal(data, tag);
    }

    [Fact]
    public async Task ReadTagAsync_SectorAligned_InsufficientData_ThrowsEndOfStreamException()
    {
        var data = new byte[StorageConstants.SectorSize - 1];
        var stream = new MemoryStream(data);
        var reader = new BlockReader();
        var metadataBuffer = new byte[StorageConstants.SectorSize];
        var tag = new byte[CryptoConstants.TagSize];

        await Assert.ThrowsAsync<EndOfStreamException>(() =>
            reader.ReadTagAsync(stream, true, tag, metadataBuffer));
    }

    [Fact]
    public async Task ReadTagAsync_NonSectorAligned_InsufficientData_ThrowsEndOfStreamException()
    {
        var data = new byte[CryptoConstants.TagSize - 1];
        var stream = new MemoryStream(data);
        var reader = new BlockReader();
        var tag = new byte[CryptoConstants.TagSize];

        await Assert.ThrowsAsync<EndOfStreamException>(() =>
            reader.ReadTagAsync(stream, false, tag, []));
    }

    [Fact]
    public async Task ReadTagAsync_CanceledToken_ThrowsOperationCanceledException()
    {
        var stream = new MemoryStream(new byte[StorageConstants.SectorSize]);
        var reader = new BlockReader();
        var metadataBuffer = new byte[StorageConstants.SectorSize];
        var tag = new byte[CryptoConstants.TagSize];
        var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            reader.ReadTagAsync(stream, true, tag, metadataBuffer, cts.Token));
    }

    [Fact]
    public async Task ReadBlockAsync_NotLastBlock_SufficientData_ReadsBufferSize()
    {
        var data = new byte[StorageConstants.BufferSize];
        for (var i = 0; i < data.Length; i++)
            data[i] = (byte)i;

        var stream = new MemoryStream(data);
        var reader = new BlockReader();
        var buffer = new byte[StorageConstants.BufferSize];

        var bytesRead = await reader.ReadBlockAsync(stream, buffer, 0, 2, CancellationToken.None);

        Assert.Equal(StorageConstants.BufferSize, bytesRead);
        Assert.Equal(data, buffer);
    }

    [Fact]
    public async Task ReadBlockAsync_NotLastBlock_InsufficientData_ReturnsZero()
    {
        var data = new byte[StorageConstants.BufferSize - 1];
        var stream = new MemoryStream(data);
        var reader = new BlockReader();
        var buffer = new byte[StorageConstants.BufferSize];

        var bytesRead = await reader.ReadBlockAsync(stream, buffer, 0, 2, CancellationToken.None);

        Assert.Equal(0, bytesRead);
    }

    [Fact]
    public async Task ReadBlockAsync_LastBlock_ExactlyBufferSize_ReadsBufferSize()
    {
        var data = new byte[StorageConstants.BufferSize];
        for (var i = 0; i < data.Length; i++)
            data[i] = (byte)i;

        var stream = new MemoryStream(data);
        var reader = new BlockReader();
        var buffer = new byte[StorageConstants.BufferSize];

        var bytesRead = await reader.ReadBlockAsync(stream, buffer, 0, 1, CancellationToken.None);

        Assert.Equal(StorageConstants.BufferSize, bytesRead);
        Assert.Equal(data, buffer);
    }

    [Fact]
    public async Task ReadBlockAsync_LastBlock_LessThanBufferSize_ReadsRemainingBytes()
    {
        var data = new byte[5000];
        for (var i = 0; i < data.Length; i++)
            data[i] = (byte)i;

        var stream = new MemoryStream(data);
        var reader = new BlockReader();
        var buffer = new byte[StorageConstants.BufferSize];

        var bytesRead = await reader.ReadBlockAsync(stream, buffer, 0, 1, CancellationToken.None);

        Assert.Equal(5000, bytesRead);
        Assert.Equal(data, buffer.Take(5000).ToArray());
    }

    [Fact]
    public async Task ReadBlockAsync_LastBlock_MoreThanBufferSize_ReadsUpToBufferSize()
    {
        var data = new byte[StorageConstants.BufferSize];
        for (var i = 0; i < data.Length; i++)
            data[i] = (byte)i;

        var stream = new MemoryStream(data);
        var reader = new BlockReader();
        var buffer = new byte[StorageConstants.BufferSize];

        var bytesRead = await reader.ReadBlockAsync(stream, buffer, 0, 1, CancellationToken.None);

        Assert.Equal(StorageConstants.BufferSize, bytesRead);
        Assert.Equal(data.Take(StorageConstants.BufferSize).ToArray(), buffer);
    }

    [Fact]
    public async Task ReadBlockAsync_LastBlock_NoBytesLeft_ReturnsZero()
    {
        var stream = new MemoryStream();
        var reader = new BlockReader();
        var buffer = new byte[StorageConstants.BufferSize];

        var bytesRead = await reader.ReadBlockAsync(stream, buffer, 0, 1, CancellationToken.None);

        Assert.Equal(0, bytesRead);
    }

    [Fact]
    public async Task ReadBlockAsync_CanceledToken_ThrowsOperationCanceledException()
    {
        var stream = new MemoryStream(new byte[StorageConstants.BufferSize]);
        var reader = new BlockReader();
        var buffer = new byte[StorageConstants.BufferSize];
        var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            reader.ReadBlockAsync(stream, buffer, 0, 1, cts.Token));
    }
}