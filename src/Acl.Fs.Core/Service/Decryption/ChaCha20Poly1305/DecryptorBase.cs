using Acl.Fs.Core.Abstractions;
using Acl.Fs.Core.Abstractions.Factory;
using Acl.Fs.Core.Abstractions.Service.Decryption.ChaCha20Poly1305;
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

namespace Acl.Fs.Core.Service.Decryption.ChaCha20Poly1305;

internal sealed class DecryptorBase(
    IChaCha20Poly1305Factory chaCha20Poly1305Factory,
    IAlignmentPolicy alignmentPolicy,
    IBlockProcessor<System.Security.Cryptography.ChaCha20Poly1305> blockProcessor,
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

    private readonly IBlockProcessor<System.Security.Cryptography.ChaCha20Poly1305> _blockProcessor =
        blockProcessor ?? throw new ArgumentNullException(nameof(blockProcessor));

    private readonly IChaCha20Poly1305Factory _chaCha20Poly1305Factory =
        chaCha20Poly1305Factory ?? throw new ArgumentNullException(nameof(chaCha20Poly1305Factory));

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

            await _auditService.AuditDecryptionStarted("ChaCha20Poly1305", cancellationToken);

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
            using var chaCha20Poly1305 = _chaCha20Poly1305Factory.Create(keyPreparation.DerivedKey);

            await _blockProcessor.ProcessAllBlocksAsync(
                sourceStream,
                destinationStream,
                chaCha20Poly1305,
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