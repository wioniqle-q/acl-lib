using Acl.Fs.Constant.Versioning;
using Acl.Fs.Core.Abstractions;
using Acl.Fs.Core.Abstractions.Factory;
using Acl.Fs.Core.Abstractions.Service.Encryption.Shared.Audit;
using Acl.Fs.Core.Abstractions.Service.Encryption.Shared.Metadata;
using Acl.Fs.Core.Abstractions.Service.Encryption.Shared.Processor;
using Acl.Fs.Core.Abstractions.Service.Encryption.XChaCha20Poly1305;
using Acl.Fs.Core.Abstractions.Service.Shared.KeyDerivation;
using Acl.Fs.Core.Models;
using Acl.Fs.Core.Policy;
using Acl.Fs.Core.Service.Encryption.Shared.Buffer;
using Acl.Fs.Core.Utility;
using Acl.Fs.Native.Factory;
using Microsoft.Extensions.Logging;
using NSec.Cryptography;
using static Acl.Fs.Constant.Cryptography.CryptoConstants;

namespace Acl.Fs.Core.Service.Encryption.XChaCha20Poly1305;

internal sealed class EncryptorBase(
    IXChaCha20Poly1305Factory xChaCha20Poly1305Factory,
    IAlignmentPolicy alignmentPolicy,
    IMetadataService metadataService,
    IBlockProcessor<Key> blockProcessor,
    IAuditService auditService,
    IKeyPreparationService keyPreparationService
)
    : IEncryptorBase
{
    private readonly IAlignmentPolicy _alignmentPolicy =
        alignmentPolicy ?? throw new ArgumentNullException(nameof(alignmentPolicy));

    private readonly IAuditService
        _auditService = auditService ?? throw new ArgumentNullException(nameof(auditService));

    private readonly IBlockProcessor<Key> _blockProcessor =
        blockProcessor ?? throw new ArgumentNullException(nameof(blockProcessor));

    private readonly IKeyPreparationService _keyPreparationService =
        keyPreparationService ?? throw new ArgumentNullException(nameof(keyPreparationService));

    private readonly IMetadataService _metadataService =
        metadataService ?? throw new ArgumentNullException(nameof(metadataService));

    private readonly IXChaCha20Poly1305Factory _xChaCha20Poly1305Factory =
        xChaCha20Poly1305Factory ?? throw new ArgumentNullException(nameof(xChaCha20Poly1305Factory));

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

            await _auditService.AuditEncryptionStarted("XChaCha20Poly1305", cancellationToken);

            var fileOptions = _alignmentPolicy.GetFileOptions();
            var metadataBufferSize = _alignmentPolicy is AlignedPolicy
                ? VersionConstants.XChaCha20Poly1305HeaderSize
                : VersionConstants.XChaCha20Poly1305UnalignedHeaderSize;

            using var bufferManager = new BufferManager(metadataBufferSize, XChaCha20Poly1305NonceSize);

            using var keyPreparation = _keyPreparationService.PrepareKey(password.Span);
            var algorithm = _xChaCha20Poly1305Factory.Create(keyPreparation.DerivedKey);
            using var cryptoKey = Key.Import(algorithm, keyPreparation.DerivedKey,
                KeyBlobFormat.RawSymmetricKey);

            await using var sourceStream =
                CryptoPrimitives.CreateInputStream(instruction.SourcePath, fileOptions, logger);
            await _auditService.AuditInputStreamOpened(instruction.SourcePath, cancellationToken);

            await using var destinationStream =
                CryptoPrimitives.CreateOutputStream(instruction.DestinationPath, fileOptions, logger);
            await _auditService.AuditOutputStreamOpened(instruction.DestinationPath, cancellationToken);

            _metadataService.PrepareMetadata(nonce.Span, sourceStream.Length, bufferManager.Salt,
                keyPreparation.Salt,
                bufferManager.MetadataBuffer, metadataBufferSize, XChaCha20Poly1305NonceSize);
            await _auditService.AuditHeaderPrepared(cancellationToken);

            await _metadataService.WriteHeaderAsync(destinationStream, bufferManager.MetadataBuffer, metadataBufferSize,
                cancellationToken);
            await _auditService.AuditHeaderWritten(cancellationToken);

            await _blockProcessor.ProcessAllBlocksAsync(
                sourceStream,
                destinationStream,
                cryptoKey,
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