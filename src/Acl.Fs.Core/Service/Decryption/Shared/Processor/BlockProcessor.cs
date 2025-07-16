using System.Runtime.CompilerServices;
using Acl.Fs.Core.Abstractions;
using Acl.Fs.Core.Abstractions.Service.Decryption.Shared.Processor;
using Acl.Fs.Core.Abstractions.Service.Decryption.Shared.Validation;
using Acl.Fs.Core.Service.Decryption.Shared.Block;
using Acl.Fs.Core.Utility;

namespace Acl.Fs.Core.Service.Decryption.Shared.Processor;

internal sealed class BlockProcessor<T>(
    IAlignmentPolicy alignmentPolicy,
    ICryptoProvider<T> cryptoProvider,
    IBlockValidator blockValidator
) : IBlockProcessor<T>
{
    private readonly IAlignmentPolicy _alignmentPolicy =
        alignmentPolicy ?? throw new ArgumentNullException(nameof(alignmentPolicy));

    private readonly IBlockValidator _blockValidator =
        blockValidator ?? throw new ArgumentNullException(nameof(blockValidator));

    private readonly ICryptoProvider<T> _cryptoProvider =
        cryptoProvider ?? throw new ArgumentNullException(nameof(cryptoProvider));

    public async Task ProcessBlockAsync(
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
        CancellationToken cancellationToken)
    {
        var isLastBlock = BlockCalculator.IsLastBlock(processedBytes, bytesRead, originalSize);
        var blockSize = _alignmentPolicy.CalculateProcessingSize(bytesRead, isLastBlock);

        CryptoOperations.DeriveNonce(salt, blockIndex, chunkNonce);

        DecryptBlock(cryptoAlgorithm, buffer, plaintext, tag, chunkNonce, salt, blockSize, blockIndex);

        _blockValidator.ValidateBlockWriteParameters(bytesRead, originalSize, processedBytes, blockSize,
            plaintext.Length);

        var bytesToWrite = BlockCalculator.CalculateBytesToWrite(bytesRead, originalSize, processedBytes);

        if (processedBytes + bytesToWrite >= originalSize)
        {
            await WriteLastBlockAsync(destinationStream, plaintext, alignedBuffer, bytesToWrite, originalSize,
                cancellationToken);
            return;
        }

        await destinationStream.WriteAsync(plaintext.AsMemory(0, bytesToWrite), cancellationToken);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void DecryptBlock(
        T cryptoAlgorithm,
        byte[] buffer,
        byte[] plaintext,
        byte[] tag,
        byte[] chunkNonce,
        byte[] salt,
        int blockSize,
        long blockIndex)
    {
        _cryptoProvider.DecryptBlock(cryptoAlgorithm, buffer, plaintext, tag, chunkNonce, salt, blockSize, blockIndex);
    }

    private async Task WriteLastBlockAsync(
        System.IO.Stream destinationStream,
        byte[] plaintext,
        byte[] alignedBuffer,
        int bytesToWrite,
        long originalSize,
        CancellationToken cancellationToken)
    {
        var alignedSize = _alignmentPolicy.CalculateProcessingSize(bytesToWrite, true);

        alignedBuffer.AsSpan(0, alignedSize).Clear();
        plaintext.AsSpan(0, bytesToWrite).CopyTo(alignedBuffer);

        await destinationStream.WriteAsync(alignedBuffer.AsMemory(0, alignedSize), cancellationToken);

        destinationStream.SetLength(originalSize);
    }
}