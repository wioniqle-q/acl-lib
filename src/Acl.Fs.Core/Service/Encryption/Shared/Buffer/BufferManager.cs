using Acl.Fs.Core.Abstractions.Service.Encryption.Shared.Buffer;
using Acl.Fs.Core.Pool;
using static Acl.Fs.Constant.Storage.StorageConstants;
using static Acl.Fs.Constant.Cryptography.CryptoConstants;

namespace Acl.Fs.Core.Service.Encryption.Shared.Buffer;

internal sealed class BufferManager(int metadataBufferSize, int nonceSize) : IBufferManager
{
    public byte[] Buffer { get; } = CryptoPool.Rent(BufferSize);
    public byte[] Ciphertext { get; } = CryptoPool.Rent(BufferSize);
    public byte[] MetadataBuffer { get; } = CryptoPool.Rent(metadataBufferSize);
    public byte[] Tag { get; } = CryptoPool.Rent(TagSize);
    public byte[] ChunkNonce { get; } = CryptoPool.Rent(nonceSize);
    public byte[] Salt { get; } = CryptoPool.Rent(SaltSize);
    public int NonceSize { get; } = nonceSize;

    public void Dispose()
    {
        CryptoPool.Return(Buffer);
        CryptoPool.Return(Ciphertext);
        CryptoPool.Return(MetadataBuffer);
        CryptoPool.Return(Tag);
        CryptoPool.Return(ChunkNonce);
        CryptoPool.Return(Salt);
    }
}