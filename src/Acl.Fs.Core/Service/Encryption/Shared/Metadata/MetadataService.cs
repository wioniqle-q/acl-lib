using System.Buffers.Binary;
using Acl.Fs.Constant.Versioning;
using Acl.Fs.Core.Abstractions.Service.Encryption.Shared.Metadata;
using Acl.Fs.Core.Utility;
using static Acl.Fs.Constant.Cryptography.CryptoConstants;

namespace Acl.Fs.Core.Service.Encryption.Shared.Metadata;

internal sealed class MetadataService : IMetadataService
{
    public void PrepareMetadata(ReadOnlySpan<byte> nonce, long originalSize, byte[] chaCha20Salt,
        ReadOnlySpan<byte> argon2Salt,
        byte[] metadataBuffer,
        int metadataBufferSize)
    {
        PrepareMetadata(nonce, originalSize, chaCha20Salt, argon2Salt, metadataBuffer, metadataBufferSize, NonceSize);
    }

    public void PrepareMetadata(ReadOnlySpan<byte> nonce, long originalSize, byte[] chaCha20Salt,
        ReadOnlySpan<byte> argon2Salt,
        byte[] metadataBuffer,
        int metadataBufferSize, int nonceSize)
    {
        CryptoOperations.PrecomputeSalt(nonce, chaCha20Salt);

        metadataBuffer.AsSpan(0, metadataBufferSize).Clear();

        metadataBuffer[0] = VersionConstants.CurrentMajorVersion;
        metadataBuffer[1] = VersionConstants.CurrentMinorVersion;

        var offset = VersionConstants.VersionHeaderSize;

        nonce[..nonceSize].CopyTo(metadataBuffer.AsSpan(offset));
        offset += nonceSize;

        BinaryPrimitives.WriteInt64LittleEndian(metadataBuffer.AsSpan(offset), originalSize);
        offset += sizeof(long);

        chaCha20Salt.CopyTo(metadataBuffer.AsSpan(offset));
        offset += SaltSize;

        argon2Salt[..Argon2IdSaltSize].CopyTo(metadataBuffer.AsSpan(offset));
    }

    public async Task WriteHeaderAsync(System.IO.Stream destinationStream, byte[] metadataBuffer,
        int metadataBufferSize, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        await destinationStream.WriteAsync(metadataBuffer.AsMemory(0, metadataBufferSize), cancellationToken);
    }
}