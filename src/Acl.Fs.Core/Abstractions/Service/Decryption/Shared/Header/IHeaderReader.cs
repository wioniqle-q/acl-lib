namespace Acl.Fs.Core.Abstractions.Service.Decryption.Shared.Header;

internal interface IHeaderReader
{
    Task<Header> ReadHeaderAsync(
        System.IO.Stream sourceStream,
        byte[] metadataBuffer,
        byte[] chaCha20Salt,
        int metadataBufferSize,
        CancellationToken cancellationToken);

    Task<Header> ReadHeaderAsync(
        System.IO.Stream sourceStream,
        byte[] metadataBuffer,
        byte[] chaCha20Salt,
        int metadataBufferSize,
        int nonceSize,
        CancellationToken cancellationToken);
}