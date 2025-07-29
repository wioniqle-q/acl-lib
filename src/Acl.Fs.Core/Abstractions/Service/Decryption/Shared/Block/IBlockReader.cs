namespace Acl.Fs.Core.Abstractions.Service.Decryption.Shared.Block;

internal interface IBlockReader
{
    Task<int> ReadBlockAsync(
        System.IO.Stream sourceStream,
        byte[] buffer,
        long blockIndex,
        long totalBlocks,
        CancellationToken cancellationToken);

    Task ReadTagAsync(
        System.IO.Stream sourceStream,
        bool isSectorAligned,
        byte[] tag,
        byte[] metadataBuffer,
        CancellationToken cancellationToken = default);
}