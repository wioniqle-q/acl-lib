namespace Acl.Fs.Core.Abstractions.Service.Encryption.Shared.Metadata;

internal interface IMetadataService
{
    void PrepareMetadata(byte[] nonce, long originalSize, byte[] salt, byte[] metadataBuffer, int metadataBufferSize);

    Task WriteHeaderAsync(System.IO.Stream destinationStream, byte[] metadataBuffer, int metadataBufferSize,
        CancellationToken cancellationToken);
}