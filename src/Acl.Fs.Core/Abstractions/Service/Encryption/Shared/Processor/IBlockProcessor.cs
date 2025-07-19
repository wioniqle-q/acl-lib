using Acl.Fs.Core.Service.Encryption.Shared.Buffer;

namespace Acl.Fs.Core.Abstractions.Service.Encryption.Shared.Processor;

internal interface IBlockProcessor<in T>
{
    Task ProcessAllBlocksAsync(
        System.IO.Stream sourceStream,
        System.IO.Stream destinationStream,
        T cryptoAlgorithm,
        BufferManager bufferManager,
        int metadataBufferSize,
        CancellationToken cancellationToken);

    Task ProcessBlockAsync(
        System.IO.Stream destinationStream,
        T cryptoAlgorithm,
        BufferManager bufferManager,
        int bytesRead,
        long blockIndex,
        long totalBlocks,
        int metadataBufferSize,
        CancellationToken cancellationToken);

    Task<int> ReadBlockAsync(
        System.IO.Stream sourceStream,
        byte[] buffer,
        long blockIndex,
        long totalBlocks,
        CancellationToken cancellationToken);

    void EncryptBlock(
        T cryptoAlgorithm,
        byte[] buffer,
        byte[] ciphertext,
        byte[] tag,
        byte[] chunkNonce,
        int alignedSize,
        long blockIndex,
        byte[] salt);

    Task WriteEncryptedBlockAsync(
        System.IO.Stream destinationStream,
        byte[] metadataBuffer,
        byte[] tag,
        byte[] ciphertext,
        int alignedSize,
        int metadataBufferSize,
        CancellationToken cancellationToken);
}