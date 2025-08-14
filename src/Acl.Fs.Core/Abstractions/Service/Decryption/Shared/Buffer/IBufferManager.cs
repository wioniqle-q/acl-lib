namespace Acl.Fs.Core.Abstractions.Service.Decryption.Shared.Buffer;

public interface IBufferManager : IDisposable
{
    byte[] Buffer { get; }
    byte[] Plaintext { get; }
    byte[] AlignedBuffer { get; }
    byte[] MetadataBuffer { get; }
    byte[] Tag { get; }
    byte[] ChunkNonce { get; }
    byte[] Salt { get; }
    int NonceSize { get; }
}