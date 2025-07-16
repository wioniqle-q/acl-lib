namespace Acl.Fs.Core.Abstractions.Service.Decryption.Shared.Header;

internal interface IHeaderReader
{
    Task<Header> ReadHeaderAsync(
        System.IO.Stream sourceStream,
        byte[] metadataBuffer,
        byte[] salt,
        int metadataBufferSize,
        CancellationToken cancellationToken);
}