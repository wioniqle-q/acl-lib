using Acl.Fs.Core.Abstractions;
using Acl.Fs.Core.Abstractions.Factory;
using Acl.Fs.Core.Abstractions.Service.Decryption.AesGcm;
using Acl.Fs.Core.Abstractions.Service.Decryption.Shared.Audit;
using Acl.Fs.Core.Abstractions.Service.Decryption.Shared.Header;
using Acl.Fs.Core.Abstractions.Service.Decryption.Shared.Processor;
using Acl.Fs.Core.Abstractions.Service.Shared.KeyDerivation;
using Acl.Fs.Core.Models;
using Acl.Fs.Core.Service.Decryption.Shared.Buffer;
using Acl.Fs.Core.Utility;
using Acl.Fs.Native.Factory;
using Microsoft.Extensions.Logging;
using static Acl.Fs.Constant.Cryptography.CryptoConstants;

namespace Acl.Fs.Core.Service.Decryption.AesGcm;

internal sealed class DecryptorBase(
    IAesGcmFactory aesGcmFactory,
    IAlignmentPolicy alignmentPolicy,
    IBlockProcessor<System.Security.Cryptography.AesGcm> blockProcessor,
    IHeaderReader headerReader,
    IAuditService auditService,
    IKeyPreparationService keyPreparationService
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

    private readonly IHeaderReader _headerReader =
        headerReader ?? throw new ArgumentNullException(nameof(headerReader));

    private readonly IKeyPreparationService _keyPreparationService =
        keyPreparationService ?? throw new ArgumentNullException(nameof(keyPreparationService));

    public async Task ExecuteDecryptionProcessAsync(
        FileTransferInstruction instruction,
        ReadOnlyMemory<byte> password,
        ILogger logger,
        CancellationToken cancellationToken)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();

            await _auditService.AuditDecryptionStarted("AesGcm", cancellationToken);

            var fileOptions = _alignmentPolicy.GetFileOptions();
            var metadataBufferSize = _alignmentPolicy.GetMetadataBufferSize();

            using var bufferManager = new BufferManager(metadataBufferSize, NonceSize);

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

            using var keyPreparation =
                _keyPreparationService.PrepareKeyWithSalt(password.Span, header.Argon2Salt.AsSpan());
            using var aesGcm = _aesGcmFactory.Create(keyPreparation.DerivedKey);

            await _blockProcessor.ProcessAllBlocksAsync(
                sourceStream,
                destinationStream,
                aesGcm,
                bufferManager,
                header,
                metadataBufferSize,
                cancellationToken);

            ShellNotifierFactory.NotifyPathUpdated(instruction.DestinationPath);

            await _auditService.AuditDecryptionCompleted(cancellationToken);
        }
        catch (Exception ex)
        {
            await _auditService.AuditDecryptionFailed(ex, cancellationToken);
            throw;
        }
    }
}