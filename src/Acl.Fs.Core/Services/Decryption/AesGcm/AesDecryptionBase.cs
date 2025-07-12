using System.Buffers.Binary;
using System.Collections.Frozen;
using System.Runtime.CompilerServices;
using Acl.Fs.Abstractions.Constants;
using Acl.Fs.Audit.Abstractions;
using Acl.Fs.Audit.Categories;
using Acl.Fs.Audit.Constants;
using Acl.Fs.Audit.Extensions;
using Acl.Fs.Core.Interfaces;
using Acl.Fs.Core.Interfaces.Decryption.AesGcm;
using Acl.Fs.Core.Interfaces.Factory;
using Acl.Fs.Core.Models;
using Acl.Fs.Core.Pool;
using Acl.Fs.Core.Resources;
using Acl.Fs.Core.Utilities;
using Microsoft.Extensions.Logging;
using static Acl.Fs.Abstractions.Constants.StorageConstants;
using static Acl.Fs.Abstractions.Constants.KeyVaultConstants;

namespace Acl.Fs.Core.Services.Decryption.AesGcm;

internal sealed class AesDecryptionBase(
    IAesGcmFactory aesGcmFactory,
    IFileVersionValidator versionValidator,
    IAlignmentPolicy alignmentPolicy,
    IAuditLogger auditLogger
) : IAesDecryptionBase
{
    private readonly IAesGcmFactory _aesGcmFactory =
        aesGcmFactory ?? throw new ArgumentNullException(nameof(aesGcmFactory));

    private readonly IAlignmentPolicy _alignmentPolicy =
        alignmentPolicy ?? throw new ArgumentNullException(nameof(alignmentPolicy));

    private readonly IAuditLogger _auditLogger =
        auditLogger ?? throw new ArgumentNullException(nameof(auditLogger));

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
                { AuditMessages.ContextKeys.Algorithm, "AES-GCM" }
            }.ToFrozenDictionary(), cancellationToken);

        var fileOptions = _alignmentPolicy.GetFileOptions();
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
            using var aesGcm = _aesGcmFactory.Create(key);

            await using var sourceStream =
                CryptoPrimitives.CreateInputStream(instruction.SourcePath, fileOptions, logger);

            await _auditLogger.AuditAsync(AuditCategory.FileAccess,
                AuditMessages.InputStreamOpened,
                AuditEventIds.DecryptionInputOpened,
                new Dictionary<string, object?>
                {
                    { AuditMessages.ContextKeys.InputFile, instruction.SourcePath }
                }.ToFrozenDictionary(), cancellationToken);

            await using var destinationStream =
                CryptoPrimitives.CreateOutputStream(instruction.DestinationPath, fileOptions, logger);

            await _auditLogger.AuditAsync(AuditCategory.FileAccess,
                AuditMessages.OutputStreamOpened,
                AuditEventIds.DecryptionOutputOpened,
                new Dictionary<string, object?>
                {
                    { AuditMessages.ContextKeys.OutputFile, instruction.DestinationPath }
                }.ToFrozenDictionary(), cancellationToken);

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
                aesGcm,
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
        System.Security.Cryptography.AesGcm aesGcm,
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
                ? (sourceStream.Length - headerLen + SectorSize + BufferSize - 1) /
                  (SectorSize + BufferSize)
                : (sourceStream.Length - headerLen + TagSize + BufferSize - 1) /
                  (TagSize + BufferSize);

            var processedBytes = 0L;

            for (blockIndex = 0L; blockIndex < totalBlocks; blockIndex++)
            {
                switch (isSectorAligned)
                {
                    case true:
                        await sourceStream.ReadExactlyAsync(
                            metadataBuffer.AsMemory(0, metadataBufferSize),
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

                var bytesRead = await ReadBlockAsync(sourceStream, buffer, blockIndex, totalBlocks, cancellationToken);
                if (bytesRead is 0)
                    break;

                await DecryptAndWriteBlockAsync(
                    destinationStream,
                    aesGcm,
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

                var available = originalSize - processedBytes;
                if (available < 0)
                    throw new InvalidOperationException(string.Format(
                        AuditMessages.ProcessFileBlocksAsyncPrefix + AuditMessages.ProcessedBytesExceeded,
                        processedBytes, originalSize));

                var bytesToWrite = (int)Math.Min(bytesRead, available);
                if (bytesToWrite < 0)
                    throw new InvalidOperationException(string.Format(
                        AuditMessages.ProcessFileBlocksAsyncPrefix + AuditMessages.NegativeBytesToWrite, bytesToWrite));

                processedBytes += bytesToWrite;

                if (processedBytes > originalSize)
                    throw new InvalidOperationException(string.Format(
                        AuditMessages.ProcessFileBlocksAsyncPrefix + AuditMessages.WrittenMoreBytesThanIntended,
                        processedBytes, originalSize));

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
        System.Security.Cryptography.AesGcm aesGcm,
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

        CryptoOperations.DeriveNonce(salt, blockIndex, chunkNonce);

        DecryptBlock(aesGcm, buffer, plaintext, tag, chunkNonce, blockSize);

        var bytesToWrite = (int)Math.Min(bytesRead, originalSize - processedBytes);
        if (bytesToWrite < 0)
            throw new InvalidOperationException(string.Format(
                AuditMessages.DecryptAndWriteBlockAsyncPrefix + AuditMessages.NegativeBytesToWrite, bytesToWrite));

        if (blockSize > plaintext.Length)
            throw new InvalidOperationException(string.Format(
                AuditMessages.DecryptAndWriteBlockAsyncPrefix + AuditMessages.BlockSizeExceedsPlaintextBuffer,
                blockSize, plaintext.Length));

        if (processedBytes + bytesToWrite > originalSize)
            throw new InvalidOperationException(string.Format(
                AuditMessages.DecryptAndWriteBlockAsyncPrefix + AuditMessages.WrittenMoreBytesThanIntended,
                processedBytes + bytesToWrite, originalSize));

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
        System.Security.Cryptography.AesGcm aesGcm,
        byte[] buffer,
        byte[] plaintext,
        byte[] tag,
        byte[] chunkNonce,
        int blockSize)
    {
        aesGcm.Decrypt(
            chunkNonce.AsSpan(0, NonceSize),
            buffer.AsSpan(0, blockSize),
            tag.AsSpan(0, TagSize),
            plaintext.AsSpan(0, blockSize));
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

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static async Task<int> ReadBlockAsync(
        System.IO.Stream sourceStream,
        byte[] buffer,
        long blockIndex,
        long totalBlocks,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            var isLastBlock = blockIndex == totalBlocks - 1;
            if (isLastBlock)
                return await sourceStream.ReadAsync(buffer.AsMemory(0, BufferSize), cancellationToken);

            await sourceStream.ReadExactlyAsync(buffer.AsMemory(0, BufferSize), cancellationToken);
            return BufferSize;
        }
        catch (EndOfStreamException)
        {
            return 0;
        }
    }
}