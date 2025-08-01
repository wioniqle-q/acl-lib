﻿namespace Acl.Fs.Core.Abstractions.Service.Encryption.Shared.Metadata;

internal interface IMetadataService
{
    void PrepareMetadata(byte[] nonce, long originalSize, byte[] chaCha20Salt, byte[] argon2Salt, byte[] metadataBuffer,
        int metadataBufferSize);

    void PrepareMetadata(byte[] nonce, long originalSize, byte[] chaCha20Salt, byte[] argon2Salt, byte[] metadataBuffer,
        int metadataBufferSize, int nonceSize);

    Task WriteHeaderAsync(System.IO.Stream destinationStream, byte[] metadataBuffer, int metadataBufferSize,
        CancellationToken cancellationToken);
}