using System.Buffers.Binary;
using System.Collections.Frozen;
using System.Runtime.CompilerServices;
using Acl.Fs.Abstractions.Constants;
using Acl.Fs.Audit.Abstractions;
using Acl.Fs.Audit.Categories;
using Acl.Fs.Audit.Constants;
using Acl.Fs.Audit.Extensions;
using Acl.Fs.Core.Interfaces;
using Acl.Fs.Core.Interfaces.Decryption.ChaCha20Poly1305;
using Acl.Fs.Core.Interfaces.Factory;
using Acl.Fs.Core.Models;
using Acl.Fs.Core.Pool;
using Acl.Fs.Core.Resources;
using Acl.Fs.Core.Utilities;
using Microsoft.Extensions.Logging;
using static Acl.Fs.Abstractions.Constants.StorageConstants;
using static Acl.Fs.Abstractions.Constants.KeyVaultConstants;

namespace Acl.Fs.Core.Services.Decryption.ChaCha20Poly1305;

internal sealed class ChaCha20Poly1305DecryptionBase(
    IFileVersionValidator versionValidator,
    IChaCha20Poly1305Factory chaCha20Poly1305Factory,
    IAlignmentPolicy alignmentPolicy,
    IAuditLogger auditLogger
)
    : IChaCha20Poly1305DecryptionBase
{
    private readonly IAlignmentPolicy _alignmentPolicy =
        alignmentPolicy ?? throw new ArgumentNullException(nameof(alignmentPolicy));

    private readonly IAuditLogger _auditLogger = auditLogger
                                                 ?? throw new ArgumentNullException(nameof(auditLogger));

    private readonly IChaCha20Poly1305Factory _chaCha20Poly1305Factory =
        chaCha20Poly1305Factory ?? throw new ArgumentNullException(nameof(chaCha20Poly1305Factory));

    private readonly IFileVersionValidator _versionValidator =
        versionValidator ?? throw new ArgumentNullException(nameof(versionValidator));

    public async Task ExecuteDecryptionProcessAsync(
        FileTransferInstruction instruction,
        byte[] key,
        ILogger logger,
        CancellationToken cancellationToken)
    {
        await _auditLogger.AuditAsync(
            AuditCategory.CryptoIntegrity,
            AuditMessages.DecryptionProcessStarted,
            AuditEventIds.DecryptionStarted,
            new Dictionary<string, object?>
            {
                { AuditMessages.ContextKeys.Algorithm, "ChaCha20Poly1305" }
            }.ToFrozenDictionary(), cancellationToken);

        var fileOptions = _alignmentPolicy.GetFileOptions();

        await using var sourceStream = StreamHelper.CreateInputStream(instruction.SourcePath, fileOptions, logger);
        await using var destinationStream =
            StreamHelper.CreateOutputStream(instruction.DestinationPath, fileOptions, logger);

        await _auditLogger.AuditAsync(AuditCategory.FileAccess,
            AuditMessages.InputStreamOpened,
            AuditEventIds.DecryptionInputOpened,
            new Dictionary<string, object?>
            {
                { AuditMessages.ContextKeys.InputFile, instruction.SourcePath }
            }.ToFrozenDictionary(), cancellationToken);

        await _auditLogger.AuditAsync(AuditCategory.FileAccess,
            AuditMessages.OutputStreamOpened,
            AuditEventIds.DecryptionOutputOpened,
            new Dictionary<string, object?>
            {
                { AuditMessages.ContextKeys.OutputFile, instruction.DestinationPath }
            }.ToFrozenDictionary(), cancellationToken);

        await ExecuteDecryptionProcessAsync(
            key,
            sourceStream,
            destinationStream,
            cancellationToken);
    }

    private async Task ExecuteDecryptionProcessAsync(
        byte[] key,
        System.IO.Stream sourceStream,
        System.IO.Stream destinationStream,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        using var chaCha20Poly1305 = _chaCha20Poly1305Factory.Create(key);
        var metadataBufferSize = _alignmentPolicy.GetMetadataBufferSize();

        var buffer = CryptoPool.Rent(BufferSize);
        var plaintext = CryptoPool.Rent(BufferSize);
        var alignedBuffer = CryptoPool.Rent(BufferSize);
        var metadataBuffer = CryptoPool.Rent(metadataBufferSize);
        var tag = CryptoPool.Rent(TagSize);
        var chunkNonce = CryptoPool.Rent(NonceSize);
        var salt = CryptoPool.Rent(SaltSize);

        try
        {
            var originalSize = await ReadHeaderAsync(sourceStream, metadataBuffer, salt, metadataBufferSize,
                cancellationToken);

            await _auditLogger.AuditAsync(
                AuditCategory.CryptoIntegrity,
                AuditMessages.DecryptionHeaderRead,
                AuditEventIds.DecryptionHeaderRead,
                cancellationToken: cancellationToken);

            await ProcessFileBlocksAsync(
                sourceStream,
                destinationStream,
                chaCha20Poly1305,
                buffer,
                plaintext,
                alignedBuffer,
                metadataBuffer,
                tag,
                chunkNonce,
                salt,
                originalSize,
                metadataBufferSize,
                cancellationToken);

            await _auditLogger.AuditAsync(
                AuditCategory.CryptoIntegrity,
                AuditMessages.DecryptionProcessCompleted,
                AuditEventIds.DecryptionCompleted,
                cancellationToken: cancellationToken);
        }
        catch (Exception ex)
        {
            await _auditLogger.AuditAsync(
                AuditCategory.CryptoIntegrity,
                AuditMessages.DecryptionFailed,
                AuditEventIds.DecryptionError,
                new Dictionary<string, object?>
                {
                    { AuditMessages.ContextKeys.ExceptionType, ex.GetType().Name },
                    { AuditMessages.ContextKeys.ExceptionMessage, ex.Message },
                    { AuditMessages.ContextKeys.StackTrace, ex.StackTrace }
                }.ToFrozenDictionary(),
                cancellationToken);

            throw;
        }
        finally
        {
            CryptoPool.Return(buffer);
            CryptoPool.Return(plaintext);
            CryptoPool.Return(alignedBuffer);
            CryptoPool.Return(metadataBuffer);
            CryptoPool.Return(tag);
            CryptoPool.Return(chunkNonce);
            CryptoPool.Return(salt);
        }
    }

    private async Task<long> ReadHeaderAsync(
        System.IO.Stream sourceStream,
        byte[] metadataBuffer,
        byte[] salt,
        int metadataBufferSize,
        CancellationToken cancellationToken)
    {
        await sourceStream.ReadExactlyAsync(
            metadataBuffer.AsMemory(0, metadataBufferSize),
            cancellationToken);

        var metadataSpan = metadataBuffer.AsSpan();

        var majorVersion = metadataSpan[0];
        var minorVersion = metadataSpan[1];

        _versionValidator.ValidateVersion(majorVersion, minorVersion);

        var nonce = metadataSpan.Slice(VersionConstants.VersionHeaderSize, NonceSize);
        var originalSize = BinaryPrimitives.ReadInt64LittleEndian(
            metadataSpan[(VersionConstants.VersionHeaderSize + NonceSize)..]);

        nonce.CopyTo(metadataBuffer.AsSpan(0, NonceSize));

        metadataSpan.Slice(VersionConstants.VersionHeaderSize + NonceSize + sizeof(long), SaltSize).CopyTo(salt);

        return originalSize;
    }

    private async Task ProcessFileBlocksAsync(
        System.IO.Stream sourceStream,
        System.IO.Stream destinationStream,
        System.Security.Cryptography.ChaCha20Poly1305 chaCha20Poly1305,
        byte[] buffer,
        byte[] plaintext,
        byte[] alignedBuffer,
        byte[] metadataBuffer,
        byte[] tag,
        byte[] chunkNonce,
        byte[] salt,
        long originalSize,
        int metadataBufferSize,
        CancellationToken cancellationToken)
    {
        var blockIndex = 0L;

        try
        {
            var isSectorAligned = metadataBufferSize is SectorSize;
            var headerLen = isSectorAligned ? SectorSize : VersionConstants.UnalignedHeaderSize;

            var totalBlocks = isSectorAligned
                ? (sourceStream.Length - headerLen + SectorSize + BufferSize - 1) / (SectorSize + BufferSize)
                : (sourceStream.Length - headerLen + TagSize + BufferSize - 1) / (TagSize + BufferSize);

            var processedBytes = 0L;

            for (blockIndex = 0L; blockIndex < totalBlocks; blockIndex++)
            {
                switch (isSectorAligned)
                {
                    case true:
                        await sourceStream.ReadExactlyAsync(
                            metadataBuffer.AsMemory(0, SectorSize),
                            cancellationToken);

                        var metadataSpan = metadataBuffer.AsSpan();
                        metadataSpan[..TagSize].CopyTo(tag);
                        break;

                    default:
                        await sourceStream.ReadExactlyAsync(
                            tag.AsMemory(0, TagSize),
                            cancellationToken);
                        break;
                }

                var bytesRead = await sourceStream.ReadAsync(
                    buffer.AsMemory(0, BufferSize),
                    cancellationToken);

                if (bytesRead is 0) break;

                await DecryptAndWriteBlockAsync(
                    destinationStream,
                    chaCha20Poly1305,
                    buffer,
                    plaintext,
                    alignedBuffer,
                    tag,
                    chunkNonce,
                    salt,
                    bytesRead,
                    blockIndex,
                    processedBytes,
                    originalSize,
                    cancellationToken);

                var bytesToWrite = (int)Math.Min(bytesRead, originalSize - processedBytes);
                processedBytes += bytesToWrite;

                if (processedBytes >= originalSize) break;
            }
        }
        catch (Exception ex)
        {
            await _auditLogger.AuditAsync(
                AuditCategory.CryptoIntegrity,
                AuditMessages.BlockDecryptionFailed,
                AuditEventIds.BlockDecryptionFailed,
                new Dictionary<string, object?>
                {
                    { AuditMessages.ContextKeys.BlockIndex, blockIndex },
                    { AuditMessages.ContextKeys.ExceptionType, ex.GetType().Name },
                    { AuditMessages.ContextKeys.ExceptionMessage, ex.Message },
                    { AuditMessages.ContextKeys.StackTrace, ex.StackTrace }
                }.ToFrozenDictionary(),
                cancellationToken);

            throw;
        }
    }

    private async Task DecryptAndWriteBlockAsync(
        System.IO.Stream destinationStream,
        System.Security.Cryptography.ChaCha20Poly1305 chaCha20Poly1305,
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
        var isLastBlock = processedBytes + bytesRead >= originalSize;
        var blockSize = _alignmentPolicy.CalculateProcessingSize(bytesRead, isLastBlock);

        CryptoHelper.DeriveNonce(salt, blockIndex, chunkNonce);

        DecryptBlock(chaCha20Poly1305, buffer, plaintext, tag, chunkNonce, blockSize, blockIndex, salt);

        var bytesToWrite = (int)Math.Min(bytesRead, originalSize - processedBytes);

        if (processedBytes + bytesToWrite >= originalSize)
        {
            await WriteLastBlockAsync(
                destinationStream,
                plaintext,
                alignedBuffer,
                bytesToWrite,
                originalSize,
                cancellationToken);
            return;
        }

        await destinationStream.WriteAsync(plaintext.AsMemory(0, bytesToWrite), cancellationToken);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void DecryptBlock(
        System.Security.Cryptography.ChaCha20Poly1305 chaCha20Poly1305,
        byte[] buffer,
        byte[] plaintext,
        byte[] tag,
        byte[] chunkNonce,
        int blockSize,
        long blockIndex,
        byte[] salt)
    {
        Span<byte> associatedData = stackalloc byte[64 + sizeof(ulong) + sizeof(int)];

        salt.AsSpan(0, Math.Min(64, salt.Length)).CopyTo(associatedData);

        BinaryPrimitives.WriteInt64LittleEndian(associatedData[64..], blockIndex);
        BinaryPrimitives.WriteInt32LittleEndian(associatedData[72..], blockSize);

        chaCha20Poly1305.Decrypt(
            chunkNonce.AsSpan(0, NonceSize),
            buffer.AsSpan(0, blockSize),
            tag.AsSpan(0, TagSize),
            plaintext.AsSpan(0, blockSize),
            associatedData);
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