using System.Buffers.Binary;
using Acl.Fs.Core.Abstractions.Service.Encryption.Shared.Processor;
using NSec.Cryptography;
using static Acl.Fs.Constant.Cryptography.CryptoConstants;

namespace Acl.Fs.Core.Service.Encryption.Shared.Provider;

internal sealed class XChaCha20Poly1305CryptoProvider : ICryptoProvider<Key>
{
    public void EncryptBlock(
        Key key,
        byte[] buffer,
        byte[] ciphertext,
        byte[] tag,
        byte[] chunkNonce,
        int alignedSize,
        long blockIndex,
        byte[] salt)
    {
        Span<byte> associatedData = stackalloc byte[64 + sizeof(long) + sizeof(int)];

        salt.AsSpan(0, Math.Min(64, salt.Length)).CopyTo(associatedData);

        BinaryPrimitives.WriteInt64LittleEndian(associatedData[64..], blockIndex);
        BinaryPrimitives.WriteInt32LittleEndian(associatedData[72..], alignedSize);

        Span<byte> fullOutput = stackalloc byte[alignedSize + TagSize];

        var algorithm = (NSec.Cryptography.XChaCha20Poly1305)key.Algorithm;

        algorithm.Encrypt(
            key,
            chunkNonce.AsSpan(0, XChaCha20Poly1305NonceSize),
            associatedData,
            buffer.AsSpan(0, alignedSize),
            fullOutput);

        fullOutput[..alignedSize].CopyTo(ciphertext.AsSpan(0, alignedSize));
        fullOutput[alignedSize..].CopyTo(tag.AsSpan(0, TagSize));
    }
}