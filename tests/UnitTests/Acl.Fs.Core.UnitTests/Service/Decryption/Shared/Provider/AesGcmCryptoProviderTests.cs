using System.Buffers.Binary;
using Acl.Fs.Core.Service.Decryption.Shared.Provider;
using static Acl.Fs.Constant.Cryptography.CryptoConstants;

namespace Acl.Fs.Core.UnitTests.Service.Decryption.Shared.Provider;

public sealed class AesGcmCryptoProviderTests
{
    [Fact]
    public void DecryptBlock_CorrectlyDecryptsData()
    {
        const long blockIndex = 0L;
        const int blockSize = 16;

        var key = new byte[32];
        for (var i = 0; i < 32; i++) key[i] = (byte)i;

        var aesGcm = new System.Security.Cryptography.AesGcm(key, TagSize);

        var nonce = new byte[NonceSize];
        for (var i = 0; i < NonceSize; i++) nonce[i] = (byte)i;

        var salt = new byte[SaltSize];
        for (var i = 0; i < NonceSize; i++) salt[i] = (byte)i;

        var plaintextOriginal = new byte[blockSize];
        for (var i = 0; i < blockSize; i++) plaintextOriginal[i] = 0xAA;

        var associatedData = new byte[SaltSize + 8 + 4];
        salt.AsSpan().CopyTo(associatedData.AsSpan(0, SaltSize));

        BinaryPrimitives.WriteInt64LittleEndian(associatedData.AsSpan(SaltSize), blockIndex);
        BinaryPrimitives.WriteInt32LittleEndian(associatedData.AsSpan(SaltSize + 8), blockSize);

        var ciphertext = new byte[blockSize];
        var tag = new byte[TagSize];

        aesGcm.Encrypt(nonce, plaintextOriginal, ciphertext, tag, associatedData);

        var provider = new AesGcmCryptoProvider();

        var plaintextDecrypted = new byte[blockSize];
        provider.DecryptBlock(aesGcm, ciphertext, plaintextDecrypted, tag, nonce, salt, blockSize, blockIndex);

        Assert.Equal(plaintextOriginal, plaintextDecrypted);
    }
}