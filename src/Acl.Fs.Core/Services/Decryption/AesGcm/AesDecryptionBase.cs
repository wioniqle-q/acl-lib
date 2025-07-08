using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using Acl.Fs.Abstractions.Constants;
using Acl.Fs.Core.Interfaces;
using Acl.Fs.Core.Interfaces.Decryption.AesGcm;
using Acl.Fs.Core.Interfaces.Factory;
using Acl.Fs.Core.Models;
using Acl.Fs.Core.Pool;
using Acl.Fs.Core.Utilities;
using Microsoft.Extensions.Logging;
using static Acl.Fs.Abstractions.Constants.StorageConstants;
using static Acl.Fs.Abstractions.Constants.KeyVaultConstants;

namespace Acl.Fs.Core.Services.Decryption.AesGcm;

internal sealed class AesDecryptionBase(
    IAesGcmFactory aesGcmFactory,
    IFileVersionValidator versionValidator,
    IAlignmentPolicy alignmentPolicy) : IAesDecryptionBase
{
    private readonly IAesGcmFactory _aesGcmFactory =
        aesGcmFactory ?? throw new ArgumentNullException(nameof(aesGcmFactory));

    private readonly IAlignmentPolicy _alignmentPolicy =
        alignmentPolicy ?? throw new ArgumentNullException(nameof(alignmentPolicy));

    private readonly IFileVersionValidator _versionValidator =
        versionValidator ?? throw new ArgumentNullException(nameof(versionValidator));

    public async Task ExecuteDecryptionProcessAsync(
        FileTransferInstruction instruction,
        byte[] key,
        ILogger logger,
        CancellationToken cancellationToken)
    {
        var fileOptions = _alignmentPolicy.GetFileOptions();

        await using var sourceStream = CryptoUtilities.CreateInputStream(instruction.SourcePath, fileOptions, logger);
        await using var destinationStream =
            CryptoUtilities.CreateOutputStream(instruction.DestinationPath, fileOptions, logger);

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

        using var aesGcm = _aesGcmFactory.Create(key);

        var buffer = CryptoPool.Rent(BufferSize);
        var plaintext = CryptoPool.Rent(BufferSize);
        var alignedBuffer = CryptoPool.Rent(BufferSize);
        var metadataBufferSize = _alignmentPolicy.GetMetadataBufferSize();
        var metadataBuffer = CryptoPool.Rent(metadataBufferSize);
        var tag = CryptoPool.Rent(TagSize);
        var chunkNonce = CryptoPool.Rent(NonceSize);
        var salt = CryptoPool.Rent(SaltSize);

        try
        {
            var originalSize = await ReadHeaderAsync(sourceStream, metadataBuffer, salt, metadataBufferSize,
                cancellationToken);

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
        var isSectorAligned = metadataBufferSize is SectorSize;

        var totalBlocks = isSectorAligned
            ? (sourceStream.Length - metadataBufferSize + metadataBufferSize + BufferSize - 1) /
              (metadataBufferSize + BufferSize)
            : (sourceStream.Length - metadataBufferSize + TagSize + BufferSize - 1) / (TagSize + BufferSize);

        var processedBytes = 0L;

        for (long blockIndex = 0; blockIndex < totalBlocks; blockIndex++)
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

            var bytesRead = await sourceStream.ReadAsync(
                buffer.AsMemory(0, BufferSize),
                cancellationToken);

            if (bytesRead is 0) break;

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

            var bytesToWrite = (int)Math.Min(bytesRead, originalSize - processedBytes);
            processedBytes += bytesToWrite;

            if (processedBytes >= originalSize) break;
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

        CryptographicUtilities.DeriveNonce(salt, blockIndex, chunkNonce);

        DecryptBlock(aesGcm, buffer, plaintext, tag, chunkNonce, blockSize);

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
}