using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using Acl.Fs.Abstractions.Constants;
using Acl.Fs.Audit.Abstractions;
using Acl.Fs.Audit.Categories;
using Acl.Fs.Audit.Constants;
using Acl.Fs.Audit.Extensions;
using Acl.Fs.Core.Interfaces;
using Acl.Fs.Core.Interfaces.Encryption.ChaCha20Poly1305;
using Acl.Fs.Core.Interfaces.Factory;
using Acl.Fs.Core.Models;
using Acl.Fs.Core.Pool;
using Acl.Fs.Core.Utilities;
using Microsoft.Extensions.Logging;
using static Acl.Fs.Abstractions.Constants.StorageConstants;
using static Acl.Fs.Abstractions.Constants.KeyVaultConstants;
using Acl.Fs.Core.Resources;

namespace Acl.Fs.Core.Services.Encryption.ChaCha20Poly1305;

internal sealed class ChaCha20Poly1305EncryptionBase(
    IChaCha20Poly1305Factory chaCha20Poly1305Factory,
    IAlignmentPolicy alignmentPolicy,
    IAuditLogger auditLogger
)
    : IChaCha20Poly1305EncryptionBase
{
    private readonly IAlignmentPolicy _alignmentPolicy =
        alignmentPolicy ?? throw new ArgumentNullException(nameof(alignmentPolicy));

    private readonly IAuditLogger _auditLogger = auditLogger
                                                 ?? throw new ArgumentNullException(nameof(auditLogger));

    private readonly IChaCha20Poly1305Factory _chaCha20Poly1305Factory =
        chaCha20Poly1305Factory ?? throw new ArgumentNullException(nameof(chaCha20Poly1305Factory));

    public async Task ExecuteEncryptionProcessAsync(
        FileTransferInstruction instruction,
        byte[] key,
        byte[] nonce,
        ILogger logger,
        CancellationToken cancellationToken)
    {
        await _auditLogger.AuditAsync(
            AuditCategory.CryptoIntegrity,
            AuditMessages.EncryptionProcessStarted,
            AuditEventIds.EncryptionStarted,
            new Dictionary<string, object?>
            {
                { AuditMessages.ContextKeys.Algorithm, "ChaCha20Poly1305" }
            }, cancellationToken);

        var fileOptions = _alignmentPolicy.GetFileOptions();
        var metadataBufferSize = _alignmentPolicy.GetMetadataBufferSize();

        await using var sourceStream = CryptoUtilities.CreateInputStream(instruction.SourcePath, fileOptions, logger);
        await using var destinationStream =
            CryptoUtilities.CreateOutputStream(instruction.DestinationPath, fileOptions, logger);

        await _auditLogger.AuditAsync(AuditCategory.FileAccess,
            AuditMessages.InputStreamOpened,
            AuditEventIds.EncryptionInputOpened,
            new Dictionary<string, object?>
            {
                { AuditMessages.ContextKeys.InputFile, instruction.SourcePath }
            }, cancellationToken);

        await _auditLogger.AuditAsync(AuditCategory.FileAccess,
            AuditMessages.OutputStreamOpened,
            AuditEventIds.EncryptionOutputOpened,
            new Dictionary<string, object?>
            {
                { AuditMessages.ContextKeys.OutputFile, instruction.DestinationPath }
            }, cancellationToken);

        using var chaCha20Poly1305 = _chaCha20Poly1305Factory.Create(key);

        var buffer = CryptoPool.Rent(BufferSize);
        var ciphertext = CryptoPool.Rent(BufferSize);
        var metadataBuffer = CryptoPool.Rent(metadataBufferSize);
        var tag = CryptoPool.Rent(TagSize);
        var chunkNonce = CryptoPool.Rent(NonceSize);
        var salt = CryptoPool.Rent(SaltSize);

        try
        {
            PrepareMetadata(nonce, sourceStream.Length, salt, metadataBuffer, metadataBufferSize);

            await _auditLogger.AuditAsync(AuditCategory.Header,
                AuditMessages.HeaderPrepared,
                AuditEventIds.EncryptionHeaderPrepared,
                cancellationToken: cancellationToken);

            await WriteHeaderAsync(destinationStream, metadataBuffer, metadataBufferSize, cancellationToken);

            await _auditLogger.AuditAsync(AuditCategory.Header,
                AuditMessages.HeaderWritten,
                AuditEventIds.EncryptionHeaderWritten,
                cancellationToken: cancellationToken);

            await ProcessFileBlocksAsync(
                sourceStream,
                destinationStream,
                chaCha20Poly1305,
                buffer,
                ciphertext,
                metadataBuffer,
                tag,
                chunkNonce,
                salt,
                metadataBufferSize,
                cancellationToken);

            await _auditLogger.AuditAsync(
                AuditCategory.CryptoIntegrity,
                AuditMessages.EncryptionProcessCompleted,
                AuditEventIds.EncryptionCompleted,
                cancellationToken: cancellationToken
            );
        }
        catch (Exception ex)
        {
            await _auditLogger.AuditAsync(
                AuditCategory.CryptoIntegrity,
                AuditMessages.EncryptionFailed,
                AuditEventIds.EncryptionError,
                new Dictionary<string, object?>
                {
                    { AuditMessages.ContextKeys.ExceptionType, ex.GetType().Name },
                    { AuditMessages.ContextKeys.ExceptionMessage, ex.Message },
                    { AuditMessages.ContextKeys.StackTrace, ex.StackTrace }
                },
                cancellationToken);

            throw;
        }
        finally
        {
            CryptoPool.Return(buffer);
            CryptoPool.Return(ciphertext);
            CryptoPool.Return(metadataBuffer);
            CryptoPool.Return(tag);
            CryptoPool.Return(chunkNonce);
            CryptoPool.Return(salt);
        }
    }

    private static void PrepareMetadata(byte[] nonce, long originalSize, byte[] salt, byte[] metadataBuffer,
        int metadataBufferSize)
    {
        CryptographicUtilities.PrecomputeSalt(nonce, salt);

        metadataBuffer.AsSpan(0, metadataBufferSize).Clear();

        metadataBuffer[0] = VersionConstants.CurrentMajorVersion;
        metadataBuffer[1] = VersionConstants.CurrentMinorVersion;

        var offset = VersionConstants.VersionHeaderSize;

        nonce.AsSpan(0, NonceSize)
            .CopyTo(metadataBuffer.AsSpan(offset));

        offset += NonceSize;

        BinaryPrimitives.WriteInt64LittleEndian(
            metadataBuffer.AsSpan(offset),
            originalSize);

        offset += sizeof(long);

        salt.CopyTo(metadataBuffer.AsSpan(offset));
    }

    private static async Task WriteHeaderAsync(
        System.IO.Stream destinationStream,
        byte[] metadataBuffer,
        int metadataBufferSize,
        CancellationToken cancellationToken)
    {
        await destinationStream.WriteAsync(
            metadataBuffer.AsMemory(0, metadataBufferSize),
            cancellationToken);
    }

    private async Task ProcessFileBlocksAsync(
        System.IO.Stream sourceStream,
        System.IO.Stream destinationStream,
        System.Security.Cryptography.ChaCha20Poly1305 chaCha20Poly1305,
        byte[] buffer,
        byte[] ciphertext,
        byte[] metadataBuffer,
        byte[] tag,
        byte[] chunkNonce,
        byte[] salt,
        int metadataBufferSize,
        CancellationToken cancellationToken)
    {
        var totalBlocks = (sourceStream.Length + BufferSize - 1) / BufferSize;

        for (var blockIndex = 0L; blockIndex < totalBlocks; blockIndex++)
        {
            var bytesRead = await sourceStream.ReadAsync(
                buffer.AsMemory(0, BufferSize),
                cancellationToken);

            if (bytesRead is 0) break;

            await EncryptAndWriteBlockAsync(
                destinationStream,
                chaCha20Poly1305,
                buffer,
                ciphertext,
                metadataBuffer,
                tag,
                chunkNonce,
                salt,
                bytesRead,
                blockIndex,
                totalBlocks,
                metadataBufferSize,
                cancellationToken);
        }
    }

    private async Task EncryptAndWriteBlockAsync(
        System.IO.Stream destinationStream,
        System.Security.Cryptography.ChaCha20Poly1305 chaCha20Poly1305,
        byte[] buffer,
        byte[] ciphertext,
        byte[] metadataBuffer,
        byte[] tag,
        byte[] chunkNonce,
        byte[] salt,
        int bytesRead,
        long blockIndex,
        long totalBlocks,
        int metadataBufferSize,
        CancellationToken cancellationToken)
    {
        try
        {
            var isLastBlock = blockIndex == totalBlocks - 1 || bytesRead < BufferSize;
            var alignedSize = _alignmentPolicy.CalculateProcessingSize(bytesRead, isLastBlock);

            if (bytesRead < alignedSize) buffer.AsSpan(bytesRead, alignedSize - bytesRead).Clear();

            CryptographicUtilities.DeriveNonce(salt, blockIndex, chunkNonce);

            EncryptBlock(chaCha20Poly1305, buffer, ciphertext, tag, chunkNonce, alignedSize, blockIndex, salt);

            await WriteEncryptedBlockAsync(destinationStream, metadataBuffer, tag, ciphertext, alignedSize,
                metadataBufferSize,
                cancellationToken);
        }
        catch (Exception ex)
        {
            await _auditLogger.AuditAsync(
                AuditCategory.CryptoIntegrity,
                AuditMessages.BlockEncryptionFailed,
                AuditEventIds.BlockEncryptionFailed,
                new Dictionary<string, object?>
                {
                    { AuditMessages.ContextKeys.BlockIndex, blockIndex },
                    { AuditMessages.ContextKeys.ExceptionType, ex.GetType().Name },
                    { AuditMessages.ContextKeys.ExceptionMessage, ex.Message },
                    { AuditMessages.ContextKeys.StackTrace, ex.StackTrace }
                },
                cancellationToken);

            throw;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void EncryptBlock(
        System.Security.Cryptography.ChaCha20Poly1305 chaCha20Poly1305,
        byte[] buffer,
        byte[] ciphertext,
        byte[] tag,
        byte[] chunkNonce,
        int alignedSize,
        long blockIndex,
        byte[] salt)
    {
        Span<byte> associatedData = stackalloc byte[64 + sizeof(long) + sizeof(int)];

        salt.AsSpan(0, Math.Min(64, salt.Length)).CopyTo(associatedData);

        BinaryPrimitives.WriteInt64LittleEndian(associatedData[64..], blockIndex);
        BinaryPrimitives.WriteInt32LittleEndian(associatedData[72..], alignedSize);

        chaCha20Poly1305.Encrypt(
            chunkNonce.AsSpan(0, NonceSize),
            buffer.AsSpan(0, alignedSize),
            ciphertext.AsSpan(0, alignedSize),
            tag.AsSpan(0, TagSize),
            associatedData);
    }

    private static async Task WriteEncryptedBlockAsync(
        System.IO.Stream destinationStream,
        byte[] metadataBuffer,
        byte[] tag,
        byte[] ciphertext,
        int alignedSize,
        int metadataBufferSize,
        CancellationToken cancellationToken)
    {
        switch (metadataBufferSize)
        {
            case SectorSize:
                metadataBuffer.AsSpan(0, metadataBufferSize).Clear();
                tag.AsSpan(0, TagSize).CopyTo(metadataBuffer);
                await destinationStream.WriteAsync(
                    metadataBuffer.AsMemory(0, metadataBufferSize),
                    cancellationToken);
                break;

            default:
                await destinationStream.WriteAsync(
                    tag.AsMemory(0, TagSize),
                    cancellationToken);
                break;
        }

        await destinationStream.WriteAsync(
            ciphertext.AsMemory(0, alignedSize),
            cancellationToken);
    }
}