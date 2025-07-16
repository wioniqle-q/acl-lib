using Acl.Fs.Core.Abstractions;
using Acl.Fs.Core.Abstractions.Factory;
using Acl.Fs.Core.Abstractions.Service.Encryption.AesGcm;
using Acl.Fs.Core.Abstractions.Service.Encryption.Shared.Audit;
using Acl.Fs.Core.Abstractions.Service.Encryption.Shared.Metadata;
using Acl.Fs.Core.Abstractions.Service.Encryption.Shared.Processor;
using Acl.Fs.Core.Abstractions.Service.Encryption.Shared.Validation;
using Acl.Fs.Core.Models;
using Acl.Fs.Core.Service.Encryption.Shared.Buffer;
using Acl.Fs.Core.Utility;
using Microsoft.Extensions.Logging;
using static Acl.Fs.Constant.Storage.StorageConstants;

namespace Acl.Fs.Core.Service.Encryption.AesGcm;

internal sealed class EncryptorBase(
    IAesGcmFactory aesGcmFactory,
    IAlignmentPolicy alignmentPolicy,
    IMetadataService metadataService,
    IBlockProcessor<System.Security.Cryptography.AesGcm> blockProcessor,
    IValidationService validationService,
    IAuditService auditService)
    : IEncryptorBase
{
    private readonly IAesGcmFactory _aesGcmFactory =
        aesGcmFactory ?? throw new ArgumentNullException(nameof(aesGcmFactory));

    private readonly IAlignmentPolicy _alignmentPolicy =
        alignmentPolicy ?? throw new ArgumentNullException(nameof(alignmentPolicy));

    private readonly IAuditService
        _auditService = auditService ?? throw new ArgumentNullException(nameof(auditService));

    private readonly IBlockProcessor<System.Security.Cryptography.AesGcm> _blockProcessor =
        blockProcessor ?? throw new ArgumentNullException(nameof(blockProcessor));

    private readonly IMetadataService _metadataService =
        metadataService ?? throw new ArgumentNullException(nameof(metadataService));

    private readonly IValidationService _validationService =
        validationService ?? throw new ArgumentNullException(nameof(validationService));

    public async Task ExecuteEncryptionProcessAsync(
        FileTransferInstruction instruction,
        byte[] key,
        byte[] nonce,
        ILogger logger,
        CancellationToken cancellationToken)
    {
        try
        {
            await _auditService.AuditEncryptionStarted("AesGcm", cancellationToken);

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

            _metadataService.PrepareMetadata(nonce, sourceStream.Length, bufferManager.Salt,
                bufferManager.MetadataBuffer, metadataBufferSize);
            await _auditService.AuditHeaderPrepared(cancellationToken);

            await _metadataService.WriteHeaderAsync(destinationStream, bufferManager.MetadataBuffer, metadataBufferSize,
                cancellationToken);
            await _auditService.AuditHeaderWritten(cancellationToken);

            await ProcessAllBlocksAsync(
                sourceStream,
                destinationStream,
                aesGcm,
                bufferManager,
                metadataBufferSize,
                cancellationToken);

            await _auditService.AuditEncryptionCompleted(cancellationToken);
        }
        catch (Exception ex)
        {
            await _auditService.AuditEncryptionFailed(ex, cancellationToken);
            throw;
        }
    }

    private async Task ProcessAllBlocksAsync(
        System.IO.Stream sourceStream,
        System.IO.Stream destinationStream,
        System.Security.Cryptography.AesGcm aesGcm,
        BufferManager bufferManager,
        int metadataBufferSize,
        CancellationToken cancellationToken)
    {
        var totalBlocks = (sourceStream.Length + BufferSize - 1) / BufferSize;
        var totalBytesRead = 0L;

        for (var blockIndex = 0L; blockIndex < totalBlocks; blockIndex++)
        {
            var bytesRead = await _blockProcessor.ReadBlockAsync(sourceStream, bufferManager.Buffer, blockIndex,
                totalBlocks, cancellationToken);
            if (bytesRead is 0)
                break;

            totalBytesRead += bytesRead;

            await _blockProcessor.ProcessBlockAsync(
                destinationStream,
                aesGcm,
                bufferManager,
                bytesRead,
                blockIndex,
                totalBlocks,
                metadataBufferSize,
                cancellationToken);
        }

        await _validationService.ValidateFileReadConsistencyAsync(totalBytesRead, sourceStream, cancellationToken);
    }
}