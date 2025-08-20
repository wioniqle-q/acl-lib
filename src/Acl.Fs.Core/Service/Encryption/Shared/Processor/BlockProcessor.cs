using System.Runtime.CompilerServices;
using Acl.Fs.Core.Abstractions;
using Acl.Fs.Core.Abstractions.Service.Encryption.Shared.Audit;
using Acl.Fs.Core.Abstractions.Service.Encryption.Shared.Processor;
using Acl.Fs.Core.Abstractions.Service.Encryption.Shared.Validation;
using Acl.Fs.Core.Service.Encryption.Shared.Buffer;
using Acl.Fs.Core.Utility;
using static Acl.Fs.Constant.Cryptography.CryptoConstants;
using static Acl.Fs.Constant.Storage.StorageConstants;

namespace Acl.Fs.Core.Service.Encryption.Shared.Processor;

internal sealed class BlockProcessor<T>(
    ICryptoProvider<T> cryptoProvider,
    IAlignmentPolicy alignmentPolicy,
    IAuditService auditService,
    IValidationService validationService
) : IBlockProcessor<T>
{
    private readonly IAlignmentPolicy _alignmentPolicy =
        alignmentPolicy ?? throw new ArgumentNullException(nameof(alignmentPolicy));

    private readonly IAuditService
        _auditService = auditService ?? throw new ArgumentNullException(nameof(auditService));

    private readonly ICryptoProvider<T> _cryptoProvider =
        cryptoProvider ?? throw new ArgumentNullException(nameof(cryptoProvider));

    private readonly IValidationService _validationService = validationService
                                                             ?? throw new ArgumentNullException(
                                                                 nameof(validationService));

    public async Task ProcessAllBlocksAsync(
        System.IO.Stream sourceStream,
        System.IO.Stream destinationStream,
        T cryptoAlgorithm,
        BufferManager bufferManager,
        int metadataBufferSize,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var totalBlocks = (sourceStream.Length + BufferSize - 1) / BufferSize;
        var totalBytesRead = 0L;

        for (var blockIndex = 0L; blockIndex < totalBlocks; blockIndex++)
        {
            var bytesRead = await ReadBlockAsync(sourceStream, bufferManager.Buffer, blockIndex,
                totalBlocks, cancellationToken);
            if (bytesRead is 0)
                break;

            totalBytesRead += bytesRead;

            await ProcessBlockAsync(
                destinationStream,
                cryptoAlgorithm,
                bufferManager,
                bytesRead,
                blockIndex,
                totalBlocks,
                metadataBufferSize,
                cancellationToken);
        }

        await _validationService.ValidateFileReadConsistencyAsync(totalBytesRead, sourceStream, cancellationToken);
    }

    public async Task ProcessBlockAsync(
        System.IO.Stream destinationStream,
        T cryptoAlgorithm,
        BufferManager bufferManager,
        int bytesRead,
        long blockIndex,
        long totalBlocks,
        int metadataBufferSize,
        CancellationToken cancellationToken)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();

            var isLastBlock = blockIndex == totalBlocks - 1 || bytesRead < BufferSize;
            var alignedSize = _alignmentPolicy.CalculateProcessingSize(bytesRead, isLastBlock);

            if (bytesRead < alignedSize)
                bufferManager.Buffer.AsSpan(bytesRead, alignedSize - bytesRead).Clear();

            CryptoOperations.DeriveNonce(bufferManager.Salt, blockIndex, bufferManager.ChunkNonce,
                bufferManager.NonceSize);

            EncryptBlock(
                cryptoAlgorithm,
                bufferManager.Buffer,
                bufferManager.Ciphertext,
                bufferManager.Tag,
                bufferManager.ChunkNonce,
                alignedSize,
                blockIndex,
                bufferManager.Salt);

            await WriteEncryptedBlockAsync(
                destinationStream,
                bufferManager.MetadataBuffer,
                bufferManager.Tag,
                bufferManager.Ciphertext,
                alignedSize,
                metadataBufferSize,
                cancellationToken);
        }
        catch (Exception ex)
        {
            await _auditService.AuditBlockEncryptionFailed(blockIndex, ex, cancellationToken);
            throw;
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

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void EncryptBlock(
        T cryptoAlgorithm,
        byte[] buffer,
        byte[] ciphertext,
        byte[] tag,
        byte[] chunkNonce,
        int alignedSize,
        long blockIndex,
        byte[] salt)
    {
        _cryptoProvider.EncryptBlock(cryptoAlgorithm, buffer, ciphertext, tag, chunkNonce, alignedSize, blockIndex,
            salt);
    }

    public async Task WriteEncryptedBlockAsync(
        System.IO.Stream destinationStream,
        byte[] metadataBuffer,
        byte[] tag,
        byte[] ciphertext,
        int alignedSize,
        int metadataBufferSize,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        switch (metadataBufferSize)
        {
            case SectorSize:
                metadataBuffer.AsSpan(0, metadataBufferSize).Clear();
                tag.AsSpan(0, TagSize).CopyTo(metadataBuffer);
                await destinationStream.WriteAsync(metadataBuffer.AsMemory(0, metadataBufferSize), cancellationToken);
                break;

            default:
                await destinationStream.WriteAsync(tag.AsMemory(0, TagSize), cancellationToken);
                break;
        }

        await destinationStream.WriteAsync(ciphertext.AsMemory(0, alignedSize), cancellationToken);
    }
}