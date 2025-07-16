using Acl.Fs.Core.Abstractions;
using Acl.Fs.Core.Abstractions.Factory;
using Acl.Fs.Core.Abstractions.Service.Decryption.AesGcm;
using Acl.Fs.Core.Abstractions.Service.Decryption.Shared.Audit;
using Acl.Fs.Core.Abstractions.Service.Decryption.Shared.Block;
using Acl.Fs.Core.Abstractions.Service.Decryption.Shared.Header;
using Acl.Fs.Core.Abstractions.Service.Decryption.Shared.Processor;
using Acl.Fs.Core.Abstractions.Service.Decryption.Shared.Validation;
using Acl.Fs.Core.Models;
using Acl.Fs.Core.Resource;
using Acl.Fs.Core.Service.Decryption.Shared.Block;
using Acl.Fs.Core.Service.Decryption.Shared.Buffer;
using Acl.Fs.Core.Utility;
using Microsoft.Extensions.Logging;
using static Acl.Fs.Constant.Storage.StorageConstants;

namespace Acl.Fs.Core.Service.Decryption.AesGcm;

internal sealed class DecryptorBase(
    IAesGcmFactory aesGcmFactory,
    IAlignmentPolicy alignmentPolicy,
    IBlockProcessor<System.Security.Cryptography.AesGcm> blockProcessor,
    IBlockReader blockReader,
    IHeaderReader headerReader,
    IAuditService auditService,
    IBlockValidator blockValidator
)
    : IDecryptorBase
{
    private readonly IAesGcmFactory _aesGcmFactory =
        aesGcmFactory ?? throw new ArgumentNullException(nameof(aesGcmFactory));

    private readonly IAlignmentPolicy _alignmentPolicy =
        alignmentPolicy ?? throw new ArgumentNullException(nameof(alignmentPolicy));

    private readonly IAuditService _auditService =
        auditService ?? throw new ArgumentNullException(nameof(auditService));

    private readonly IBlockProcessor<System.Security.Cryptography.AesGcm> _blockProcessor =
        blockProcessor ?? throw new ArgumentNullException(nameof(blockProcessor));

    private readonly IBlockReader _blockReader =
        blockReader ?? throw new ArgumentNullException(nameof(blockReader));

    private readonly IBlockValidator _blockValidator =
        blockValidator ?? throw new ArgumentNullException(nameof(blockValidator));

    private readonly IHeaderReader _headerReader =
        headerReader ?? throw new ArgumentNullException(nameof(headerReader));

    public async Task ExecuteDecryptionProcessAsync(
        FileTransferInstruction instruction,
        byte[] key,
        ILogger logger,
        CancellationToken cancellationToken)
    {
        try
        {
            await _auditService.AuditDecryptionStarted("AesGcm", cancellationToken);

            var fileOptions = _alignmentPolicy.GetFileOptions();
            var metadataBufferSize = _alignmentPolicy.GetMetadataBufferSize();

            using var bufferManager = new BufferManager(metadataBufferSize);
            using var aesGcm = _aesGcmFactory.Create(key);

            await using var sourceStream =
                CryptoPrimitives.CreateInputStream(instruction.SourcePath, fileOptions, logger);
            await _auditService.AuditInputStreamOpened(instruction.SourcePath, cancellationToken);

            await using var destinationStream =
                CryptoPrimitives.CreateOutputStream(instruction.DestinationPath, fileOptions, logger);
            await _auditService.AuditOutputStreamOpened(instruction.DestinationPath, cancellationToken);

            var header = await _headerReader.ReadHeaderAsync(
                sourceStream,
                bufferManager.MetadataBuffer,
                bufferManager.Salt,
                metadataBufferSize,
                cancellationToken);

            await _auditService.AuditHeaderRead(cancellationToken);

            await ProcessAllBlocksAsync(
                sourceStream,
                destinationStream,
                aesGcm,
                bufferManager,
                header,
                metadataBufferSize,
                cancellationToken);

            await _auditService.AuditDecryptionCompleted(cancellationToken);
        }
        catch (Exception ex)
        {
            await _auditService.AuditDecryptionFailed(ex, cancellationToken);
            throw;
        }
    }

    private async Task ProcessAllBlocksAsync(
        System.IO.Stream sourceStream,
        System.IO.Stream destinationStream,
        System.Security.Cryptography.AesGcm aesCcm,
        BufferManager resources,
        Header header,
        int metadataBufferSize,
        CancellationToken cancellationToken)
    {
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

                await _blockProcessor.ProcessBlockAsync(
                    destinationStream,
                    aesCcm,
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
}