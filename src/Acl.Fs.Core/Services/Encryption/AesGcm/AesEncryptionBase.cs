using System.Buffers.Binary;
using System.Collections.Frozen;
using System.Runtime.CompilerServices;
using Acl.Fs.Abstractions.Constants;
using Acl.Fs.Audit.Abstractions;
using Acl.Fs.Audit.Categories;
using Acl.Fs.Audit.Constants;
using Acl.Fs.Audit.Extensions;
using Acl.Fs.Core.Interfaces;
using Acl.Fs.Core.Interfaces.Encryption.AesGcm;
using Acl.Fs.Core.Interfaces.Factory;
using Acl.Fs.Core.Models;
using Acl.Fs.Core.Pool;
using Acl.Fs.Core.Resources;
using Acl.Fs.Core.Utilities;
using Microsoft.Extensions.Logging;
using static Acl.Fs.Abstractions.Constants.StorageConstants;
using static Acl.Fs.Abstractions.Constants.KeyVaultConstants;

namespace Acl.Fs.Core.Services.Encryption.AesGcm;

internal sealed class AesEncryptionBase(
    IAesGcmFactory aesGcmFactory,
    IAlignmentPolicy alignmentPolicy,
    IAuditLogger auditLogger
)
    : IAesEncryptionBase
{
    private readonly IAesGcmFactory _aesGcmFactory =
        aesGcmFactory ?? throw new ArgumentNullException(nameof(aesGcmFactory));

    private readonly IAlignmentPolicy _alignmentPolicy =
        alignmentPolicy ?? throw new ArgumentNullException(nameof(alignmentPolicy));

    private readonly IAuditLogger _auditLogger = auditLogger
                                                 ?? throw new ArgumentNullException(nameof(auditLogger));

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
                { AuditMessages.ContextKeys.Algorithm, "AES-GCM" }
            }.ToFrozenDictionary(), cancellationToken);

        var fileOptions = _alignmentPolicy.GetFileOptions();
        var metadataBufferSize = _alignmentPolicy.GetMetadataBufferSize();

        await using var sourceStream = StreamHelper.CreateInputStream(instruction.SourcePath, fileOptions, logger);
        await using var destinationStream =
            StreamHelper.CreateOutputStream(instruction.DestinationPath, fileOptions, logger);

        await _auditLogger.AuditAsync(AuditCategory.FileAccess,
            AuditMessages.InputStreamOpened,
            AuditEventIds.EncryptionInputOpened,
            new Dictionary<string, object?>
            {
                { AuditMessages.ContextKeys.InputFile, instruction.SourcePath }
            }.ToFrozenDictionary(), cancellationToken);

        await _auditLogger.AuditAsync(AuditCategory.FileAccess,
            AuditMessages.OutputStreamOpened,
            AuditEventIds.EncryptionOutputOpened,
            new Dictionary<string, object?>
            {
                { AuditMessages.ContextKeys.OutputFile, instruction.DestinationPath }
            }.ToFrozenDictionary(), cancellationToken);

        using var aesGcm = _aesGcmFactory.Create(key);

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
                aesGcm,
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
                }.ToFrozenDictionary(),
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
        CryptoHelper.PrecomputeSalt(nonce, salt);

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
        System.Security.Cryptography.AesGcm aesGcm,
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
                aesGcm,
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
        System.Security.Cryptography.AesGcm aesGcm,
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

            CryptoHelper.DeriveNonce(salt, blockIndex, chunkNonce);

            EncryptBlock(aesGcm, buffer, ciphertext, tag, chunkNonce, alignedSize);

            await WriteEncryptedBlockAsync(destinationStream, metadataBuffer, tag, ciphertext, alignedSize,
                metadataBufferSize, cancellationToken);
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
                }.ToFrozenDictionary(),
                cancellationToken);

            throw;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void EncryptBlock(
        System.Security.Cryptography.AesGcm aesGcm,
        byte[] buffer,
        byte[] ciphertext,
        byte[] tag,
        byte[] chunkNonce,
        int alignedSize)
    {
        aesGcm.Encrypt(
            chunkNonce.AsSpan(0, NonceSize),
            buffer.AsSpan(0, alignedSize),
            ciphertext.AsSpan(0, alignedSize),
            tag.AsSpan(0, TagSize));
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