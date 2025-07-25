using Acl.Fs.Core.Abstractions.Service.Decryption.Shared.Buffer;
using Acl.Fs.Core.Pool;
using static Acl.Fs.Constant.Cryptography.CryptoConstants;
using static Acl.Fs.Constant.Storage.StorageConstants;

namespace Acl.Fs.Core.Service.Decryption.Shared.Buffer;

internal sealed class BufferManager(int metadataBufferSize, int nonceSize) : IBufferManager
{
    public byte[] Buffer { get; } = CryptoPool.Rent(BufferSize);
    public byte[] Plaintext { get; } = CryptoPool.Rent(BufferSize);
    public byte[] AlignedBuffer { get; } = CryptoPool.Rent(BufferSize);
    public byte[] MetadataBuffer { get; } = CryptoPool.Rent(metadataBufferSize);
    public byte[] Tag { get; } = CryptoPool.Rent(TagSize);
    public byte[] ChunkNonce { get; } = CryptoPool.Rent(nonceSize);
    public byte[] Salt { get; } = CryptoPool.Rent(SaltSize);
    public int NonceSize { get; } = nonceSize;

    public void Dispose()
    {
        CryptoPool.Return(Buffer);
        CryptoPool.Return(Plaintext);
        CryptoPool.Return(AlignedBuffer);
        CryptoPool.Return(MetadataBuffer);
        CryptoPool.Return(Tag);
        CryptoPool.Return(ChunkNonce);
        CryptoPool.Return(Salt);
    }
}