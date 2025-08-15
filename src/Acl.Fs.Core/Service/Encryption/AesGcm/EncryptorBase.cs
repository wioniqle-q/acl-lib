using Acl.Fs.Core.Abstractions;
using Acl.Fs.Core.Abstractions.Factory;
using Acl.Fs.Core.Abstractions.Service.Encryption.AesGcm;
using Acl.Fs.Core.Abstractions.Service.Encryption.Shared.Audit;
using Acl.Fs.Core.Abstractions.Service.Encryption.Shared.Metadata;
using Acl.Fs.Core.Abstractions.Service.Encryption.Shared.Processor;
using Acl.Fs.Core.Abstractions.Service.Shared.KeyDerivation;
using Acl.Fs.Core.Models;
using Acl.Fs.Core.Service.Encryption.Shared.Buffer;
using Acl.Fs.Core.Utility;
using Acl.Fs.Native.Factory;
using Microsoft.Extensions.Logging;
using static Acl.Fs.Constant.Cryptography.CryptoConstants;

namespace Acl.Fs.Core.Service.Encryption.AesGcm;

internal sealed class EncryptorBase(
    IAesGcmFactory aesGcmFactory,
    IAlignmentPolicy alignmentPolicy,
    IMetadataService metadataService,
    IBlockProcessor<System.Security.Cryptography.AesGcm> blockProcessor,
    IAuditService auditService,
    IKeyPreparationService keyPreparationService
)
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

    private readonly IKeyPreparationService _keyPreparationService =
        keyPreparationService ?? throw new ArgumentNullException(nameof(keyPreparationService));

    private readonly IMetadataService _metadataService =
        metadataService ?? throw new ArgumentNullException(nameof(metadataService));

    public async Task ExecuteEncryptionProcessAsync(
        FileTransferInstruction instruction,
        ReadOnlyMemory<byte> password,
        ReadOnlyMemory<byte> nonce,
        ILogger logger,
        CancellationToken cancellationToken)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();

            await _auditService.AuditEncryptionStarted("AesGcm", cancellationToken);

            var fileOptions = _alignmentPolicy.GetFileOptions();
            var metadataBufferSize = _alignmentPolicy.GetMetadataBufferSize();

            using var bufferManager = new BufferManager(metadataBufferSize, NonceSize);

            using var keyPreparation = _keyPreparationService.PrepareKey(password.Span);
            using var aesGcm = _aesGcmFactory.Create(keyPreparation.DerivedKey);

            await using var sourceStream =
                CryptoPrimitives.CreateInputStream(instruction.SourcePath, fileOptions, logger);
            await _auditService.AuditInputStreamOpened(instruction.SourcePath, cancellationToken);

            await using var destinationStream =
                CryptoPrimitives.CreateOutputStream(instruction.DestinationPath, fileOptions, logger);
            await _auditService.AuditOutputStreamOpened(instruction.DestinationPath, cancellationToken);

            _metadataService.PrepareMetadata(nonce.Span, sourceStream.Length, bufferManager.Salt,
                keyPreparation.Salt,
                bufferManager.MetadataBuffer, metadataBufferSize);
            await _auditService.AuditHeaderPrepared(cancellationToken);

            await _metadataService.WriteHeaderAsync(destinationStream, bufferManager.MetadataBuffer, metadataBufferSize,
                cancellationToken);
            await _auditService.AuditHeaderWritten(cancellationToken);

            await _blockProcessor.ProcessAllBlocksAsync(
                sourceStream,
                destinationStream,
                aesGcm,
                bufferManager,
                metadataBufferSize,
                cancellationToken);

            ShellNotifierFactory.NotifyPathUpdated(instruction.DestinationPath);

            await _auditService.AuditEncryptionCompleted(cancellationToken);
        }
        catch (Exception ex)
        {
            await _auditService.AuditEncryptionFailed(ex, cancellationToken);
            throw;
        }
    }
}