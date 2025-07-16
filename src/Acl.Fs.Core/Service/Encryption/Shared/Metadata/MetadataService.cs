using System.Buffers.Binary;
using Acl.Fs.Constant.Versioning;
using Acl.Fs.Core.Abstractions.Service.Encryption.Shared.Metadata;
using Acl.Fs.Core.Utility;
using static Acl.Fs.Constant.Cryptography.KeyVaultConstants;

namespace Acl.Fs.Core.Service.Encryption.Shared.Metadata;

internal sealed class MetadataService : IMetadataService
{
    public void PrepareMetadata(byte[] nonce, long originalSize, byte[] salt, byte[] metadataBuffer,
        int metadataBufferSize)
    {
        CryptoOperations.PrecomputeSalt(nonce, salt);

        metadataBuffer.AsSpan(0, metadataBufferSize).Clear();

        metadataBuffer[0] = VersionConstants.CurrentMajorVersion;
        metadataBuffer[1] = VersionConstants.CurrentMinorVersion;

        var offset = VersionConstants.VersionHeaderSize;

        nonce.AsSpan(0, NonceSize).CopyTo(metadataBuffer.AsSpan(offset));
        offset += NonceSize;

        BinaryPrimitives.WriteInt64LittleEndian(metadataBuffer.AsSpan(offset), originalSize);
        offset += sizeof(long);

        salt.CopyTo(metadataBuffer.AsSpan(offset));
    }

    public async Task WriteHeaderAsync(System.IO.Stream destinationStream, byte[] metadataBuffer,
        int metadataBufferSize, CancellationToken cancellationToken)
    {
        await destinationStream.WriteAsync(metadataBuffer.AsMemory(0, metadataBufferSize), cancellationToken);
    }
}