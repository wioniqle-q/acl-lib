using Acl.Fs.Core.Service.Decryption.Shared.Buffer;

namespace Acl.Fs.Core.Abstractions.Service.Decryption.Shared.Processor;

internal interface IBlockProcessor<in T>
{
    Task ProcessAllBlocksAsync(
        System.IO.Stream sourceStream,
        System.IO.Stream destinationStream,
        T cryptoAlgorithm,
        BufferManager resources,
        Header.Header header,
        int metadataBufferSize,
        CancellationToken cancellationToken);

    Task ProcessBlockAsync(
        System.IO.Stream destinationStream,
        T cryptoAlgorithm,
        byte[] buffer,
        byte[] plaintext,
        byte[] alignedBuffer,
        byte[] tag,
        byte[] chunkNonce,
        byte[] salt,
        int bytesRead,
        long blockIndex,
        long processedBytes,
        long originalSize,
        int nonceSize,
        CancellationToken cancellationToken);
}