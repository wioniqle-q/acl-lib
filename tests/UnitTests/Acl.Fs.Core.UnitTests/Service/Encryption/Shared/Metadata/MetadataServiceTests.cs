using System.Buffers.Binary;
using Acl.Fs.Constant.Versioning;
using Acl.Fs.Core.Service.Encryption.Shared.Metadata;
using static Acl.Fs.Constant.Cryptography.CryptoConstants;

namespace Acl.Fs.Core.UnitTests.Service.Encryption.Shared.Metadata;

public sealed class MetadataServiceTests
{
    [Fact]
    public void PrepareMetadata_SetsCorrectValues()
    {
        const long originalSize = 1000;
        const int bufferSize = 102;

        var dataSize = VersionConstants.VersionHeaderSize + NonceSize + sizeof(long) + SaltSize + Argon2IdSaltSize;

        var nonce = new byte[NonceSize];
        for (var i = 0; i < NonceSize; i++) nonce[i] = (byte)(i + 1);

        var chaCha20Salt = new byte[SaltSize];
        for (var i = 0; i < SaltSize; i++) chaCha20Salt[i] = (byte)(i + 10);

        var argon2Salt = new byte[Argon2IdSaltSize];
        for (var i = 0; i < Argon2IdSaltSize; i++) argon2Salt[i] = (byte)(i + 20);

        var metadataBuffer = new byte[bufferSize];
        for (var i = 0; i < bufferSize; i++) metadataBuffer[i] = 0xFF;

        var service = new MetadataService();

        service.PrepareMetadata(nonce, originalSize, chaCha20Salt, argon2Salt, metadataBuffer, bufferSize);

        Assert.Equal(VersionConstants.CurrentMajorVersion, metadataBuffer[0]);
        Assert.Equal(VersionConstants.CurrentMinorVersion, metadataBuffer[1]);

        var offset = VersionConstants.VersionHeaderSize;

        for (var i = 0; i < NonceSize; i++)
            Assert.Equal(nonce[i], metadataBuffer[offset + i]);
        offset += NonceSize;

        var readSize = BinaryPrimitives.ReadInt64LittleEndian(metadataBuffer.AsSpan(offset));
        Assert.Equal(originalSize, readSize);
        offset += sizeof(long);

        for (var i = 0; i < SaltSize; i++)
            Assert.Equal(chaCha20Salt[i], metadataBuffer[offset + i]);
        offset += SaltSize;

        for (var i = 0; i < Argon2IdSaltSize; i++)
            Assert.Equal(argon2Salt[i], metadataBuffer[offset + i]);

        for (var i = dataSize; i < bufferSize; i++)
            Assert.Equal(0, metadataBuffer[i]);
    }

    [Fact]
    public async Task WriteHeaderAsync_WritesCorrectData()
    {
        const int metadataSize = 70;
        const int bufferSize = 100;

        var metadataBuffer = new byte[bufferSize];
        for (var i = 0; i < bufferSize; i++) metadataBuffer[i] = (byte)i;

        using var stream = new MemoryStream();
        var service = new MetadataService();

        await service.WriteHeaderAsync(stream, metadataBuffer, metadataSize, CancellationToken.None);

        var writtenData = stream.ToArray();
        Assert.Equal(metadataSize, writtenData.Length);

        for (var i = 0; i < metadataSize; i++)
            Assert.Equal(metadataBuffer[i], writtenData[i]);
    }
}