using System.Runtime.CompilerServices;
using Acl.Fs.Core.Abstractions;
using Acl.Fs.Core.Abstractions.Service.Decryption.Shared.Audit;
using Acl.Fs.Core.Abstractions.Service.Decryption.Shared.Block;
using Acl.Fs.Core.Abstractions.Service.Decryption.Shared.Processor;
using Acl.Fs.Core.Abstractions.Service.Decryption.Shared.Validation;
using Acl.Fs.Core.Resource;
using Acl.Fs.Core.Service.Decryption.Shared.Block;
using Acl.Fs.Core.Service.Decryption.Shared.Buffer;
using Acl.Fs.Core.Utility;
using static Acl.Fs.Constant.Storage.StorageConstants;

namespace Acl.Fs.Core.Service.Decryption.Shared.Processor;

internal sealed class BlockProcessor<T>(
    IAlignmentPolicy alignmentPolicy,
    ICryptoProvider<T> cryptoProvider,
    IBlockValidator blockValidator,
    IBlockReader blockReader,
    IAuditService auditService
) : IBlockProcessor<T>
{
    private readonly IAlignmentPolicy _alignmentPolicy =
        alignmentPolicy ?? throw new ArgumentNullException(nameof(alignmentPolicy));

    private readonly IAuditService _auditService =
        auditService ?? throw new ArgumentNullException(nameof(auditService));

    private readonly IBlockReader _blockReader =
        blockReader ?? throw new ArgumentNullException(nameof(blockReader));

    private readonly IBlockValidator _blockValidator =
        blockValidator ?? throw new ArgumentNullException(nameof(blockValidator));

    private readonly ICryptoProvider<T> _cryptoProvider =
        cryptoProvider ?? throw new ArgumentNullException(nameof(cryptoProvider));

    public async Task ProcessAllBlocksAsync(
        System.IO.Stream sourceStream,
        System.IO.Stream destinationStream,
        T cryptoAlgorithm,
        BufferManager resources,
        Abstractions.Service.Decryption.Shared.Header.Header header,
        int metadataBufferSize,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var blockIndex = 0L;
        var processedBytes = 0L;

        try
        {
            var totalBlocks = BlockCalculator.CalculateTotalBlocks(sourceStream.Length, metadataBufferSize, BufferSize);

            for (blockIndex = 0L; blockIndex < totalBlocks; blockIndex++)
            {
                await _blockReader.ReadTagAsync(
                    sourceStream,
                    metadataBufferSize is SectorSize,
                    resources.Tag,
                    resources.MetadataBuffer,
                    cancellationToken);

                var bytesRead = await _blockReader.ReadBlockAsync(
                    sourceStream,
                    resources.Buffer,
                    blockIndex,
                    totalBlocks,
                    cancellationToken);

                if (bytesRead is 0) break;

                await ProcessBlockAsync(
                    destinationStream,
                    cryptoAlgorithm,
                    resources.Buffer,
                    resources.Plaintext,
                    resources.AlignedBuffer,
                    resources.Tag,
                    resources.ChunkNonce,
                    resources.Salt,
                    bytesRead,
                    blockIndex,
                    processedBytes,
                    header.OriginalSize,
                    resources.NonceSize,
                    cancellationToken);

                processedBytes = _blockValidator.ValidateAndCalculateBytes(
                    processedBytes,
                    header.OriginalSize,
                    bytesRead,
                    AuditMessages.ProcessFileBlocksAsyncPrefix);

                if (processedBytes >= header.OriginalSize) break;
            }
        }
        catch (Exception ex)
        {
            await _auditService.AuditBlockDecryptionFailed(blockIndex, ex, cancellationToken);
            throw;
        }
    }

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
        int nonceSize,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var isLastBlock = BlockCalculator.IsLastBlock(processedBytes, bytesRead, originalSize);
        var blockSize = _alignmentPolicy.CalculateProcessingSize(bytesRead, isLastBlock);

        CryptoOperations.DeriveNonce(salt, blockIndex, chunkNonce, nonceSize);

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
        cancellationToken.ThrowIfCancellationRequested();

        var alignedSize = _alignmentPolicy.CalculateProcessingSize(bytesToWrite, true);

        alignedBuffer.AsSpan(0, alignedSize).Clear();
        plaintext.AsSpan(0, bytesToWrite).CopyTo(alignedBuffer);

        await destinationStream.WriteAsync(alignedBuffer.AsMemory(0, alignedSize), cancellationToken);

        destinationStream.SetLength(originalSize);
    }
}