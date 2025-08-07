using System.Buffers.Binary;
using Acl.Fs.Core.Service.Decryption.Shared.Provider;
using static Acl.Fs.Constant.Cryptography.CryptoConstants;

namespace Acl.Fs.Core.UnitTests.Service.Decryption.Shared.Provider;

public sealed class ChaCha20Poly1305CryptoProviderTests
{
    [Fact]
    public void DecryptBlock_CorrectlyDecryptsData()
    {
        const long blockIndex = 0L;
        const int blockSize = 16;

        var key = new byte[32];
        for (var i = 0; i < 32; i++) key[i] = (byte)i;

        var chaCha20Poly1305 = new System.Security.Cryptography.ChaCha20Poly1305(key);

        var nonce = new byte[NonceSize];
        for (var i = 0; i < NonceSize; i++) nonce[i] = (byte)i;

        var salt = new byte[SaltSize];
        for (var i = 0; i < SaltSize; i++) salt[i] = (byte)i;

        var plaintextOriginal = new byte[blockSize];
        for (var i = 0; i < blockSize; i++) plaintextOriginal[i] = 0xAA;

        var associatedData = new byte[SaltSize + 8 + 4];
        salt.AsSpan().CopyTo(associatedData.AsSpan(0, SaltSize));

        BinaryPrimitives.WriteInt64LittleEndian(associatedData.AsSpan(SaltSize), blockIndex);
        BinaryPrimitives.WriteInt32LittleEndian(associatedData.AsSpan(SaltSize + 8), blockSize);

        var ciphertext = new byte[blockSize];
        var tag = new byte[TagSize];

        chaCha20Poly1305.Encrypt(nonce, plaintextOriginal, ciphertext, tag, associatedData);

        var provider = new ChaCha20Poly1305CryptoProvider();

        var plaintextDecrypted = new byte[blockSize];
        provider.DecryptBlock(chaCha20Poly1305, ciphertext, plaintextDecrypted, tag, nonce, salt, blockSize,
            blockIndex);

        Assert.Equal(plaintextOriginal, plaintextDecrypted);
    }
}