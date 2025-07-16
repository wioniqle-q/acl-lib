namespace Acl.Fs.Core.Abstractions.Service.Decryption.Shared.Processor;

internal interface IBlockProcessor<in T>
{
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
        CancellationToken cancellationToken);
}