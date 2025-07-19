using Acl.Fs.Core.Abstractions.Service.Decryption.Shared.Block;
using static Acl.Fs.Constant.Storage.StorageConstants;
using static Acl.Fs.Constant.Cryptography.CryptoConstants;

namespace Acl.Fs.Core.Service.Decryption.Shared.Block;

internal sealed class BlockReader : IBlockReader
{
    public async Task ReadTagAsync(
        System.IO.Stream sourceStream,
        bool isSectorAligned,
        byte[] tag,
        byte[] metadataBuffer,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        switch (isSectorAligned)
        {
            case true:
                await sourceStream.ReadExactlyAsync(
                    metadataBuffer.AsMemory(0, SectorSize),
                    cancellationToken);

                var metadataSpan = metadataBuffer.AsSpan();
                metadataSpan[..TagSize].CopyTo(tag);
                break;

            default:
                await sourceStream.ReadExactlyAsync(
                    tag.AsMemory(0, TagSize),
                    cancellationToken);
                break;
        }
    }

    public async Task<int> ReadBlockAsync(
        System.IO.Stream sourceStream,
        byte[] buffer,
        long blockIndex,
        long totalBlocks,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            var isLastBlock = blockIndex == totalBlocks - 1;
            if (isLastBlock)
                return await sourceStream.ReadAsync(buffer.AsMemory(0, BufferSize), cancellationToken);

            await sourceStream.ReadExactlyAsync(buffer.AsMemory(0, BufferSize), cancellationToken);
            return BufferSize;
        }
        catch (EndOfStreamException)
        {
            return 0;
        }
    }
}