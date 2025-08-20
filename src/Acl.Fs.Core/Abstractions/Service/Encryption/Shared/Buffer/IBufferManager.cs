namespace Acl.Fs.Core.Abstractions.Service.Encryption.Shared.Buffer;

internal interface IBufferManager : IDisposable
{
    byte[] Buffer { get; }
    byte[] Ciphertext { get; }
    byte[] MetadataBuffer { get; }
    byte[] Tag { get; }
    byte[] ChunkNonce { get; }
    byte[] Salt { get; }
    int NonceSize { get; }
}