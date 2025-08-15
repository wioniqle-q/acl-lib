using Acl.Fs.Constant.Versioning;
using Acl.Fs.Core.Abstractions;
using Acl.Fs.Core.Abstractions.Factory;
using Acl.Fs.Core.Abstractions.Service.Decryption.Shared.Audit;
using Acl.Fs.Core.Abstractions.Service.Decryption.Shared.Header;
using Acl.Fs.Core.Abstractions.Service.Decryption.Shared.Processor;
using Acl.Fs.Core.Abstractions.Service.Decryption.XChaCha20Poly1305;
using Acl.Fs.Core.Abstractions.Service.Shared.KeyDerivation;
using Acl.Fs.Core.Models;
using Acl.Fs.Core.Policy;
using Acl.Fs.Core.Service.Decryption.Shared.Buffer;
using Acl.Fs.Core.Utility;
using Acl.Fs.Native.Factory;
using Microsoft.Extensions.Logging;
using NSec.Cryptography;
using static Acl.Fs.Constant.Cryptography.CryptoConstants;

namespace Acl.Fs.Core.Service.Decryption.XChaCha20Poly1305;

internal sealed class DecryptorBase(
    IXChaCha20Poly1305Factory xChaCha20Poly1305Factory,
    IAlignmentPolicy alignmentPolicy,
    IBlockProcessor<Key> blockProcessor,
    IHeaderReader headerReader,
    IAuditService auditService,
    IKeyPreparationService keyPreparationService
)
    : IDecryptorBase
{
    private readonly IAlignmentPolicy _alignmentPolicy =
        alignmentPolicy ?? throw new ArgumentNullException(nameof(alignmentPolicy));

    private readonly IAuditService _auditService =
        auditService ?? throw new ArgumentNullException(nameof(auditService));

    private readonly IBlockProcessor<Key> _blockProcessor =
        blockProcessor ?? throw new ArgumentNullException(nameof(blockProcessor));

    private readonly IHeaderReader _headerReader =
        headerReader ?? throw new ArgumentNullException(nameof(headerReader));

    private readonly IKeyPreparationService _keyPreparationService =
        keyPreparationService ?? throw new ArgumentNullException(nameof(keyPreparationService));

    private readonly IXChaCha20Poly1305Factory _xChaCha20Poly1305Factory =
        xChaCha20Poly1305Factory ?? throw new ArgumentNullException(nameof(xChaCha20Poly1305Factory));

    public async Task ExecuteDecryptionProcessAsync(
        FileTransferInstruction instruction,
        ReadOnlyMemory<byte> password,
        ILogger logger,
        CancellationToken cancellationToken)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();

            await _auditService.AuditDecryptionStarted("XChaCha20Poly1305", cancellationToken);

            var fileOptions = _alignmentPolicy.GetFileOptions();
            var metadataBufferSize = _alignmentPolicy is AlignedPolicy
                ? VersionConstants.XChaCha20Poly1305HeaderSize
                : VersionConstants.XChaCha20Poly1305UnalignedHeaderSize;

            using var bufferManager = new BufferManager(metadataBufferSize, XChaCha20Poly1305NonceSize);

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
                XChaCha20Poly1305NonceSize,
                cancellationToken);

            await _auditService.AuditHeaderRead(cancellationToken);

            using var keyPreparation =
                _keyPreparationService.PrepareKeyWithSalt(password.Span, header.Argon2Salt.AsSpan());
            var algorithm = _xChaCha20Poly1305Factory.Create(keyPreparation.DerivedKey);
            using var cryptoKey = Key.Import(algorithm, keyPreparation.DerivedKey,
                KeyBlobFormat.RawSymmetricKey);

            await _blockProcessor.ProcessAllBlocksAsync(
                sourceStream,
                destinationStream,
                cryptoKey,
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