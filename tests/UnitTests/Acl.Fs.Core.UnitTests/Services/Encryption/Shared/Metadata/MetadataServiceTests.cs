using System.Buffers.Binary;
using Acl.Fs.Core.Service.Encryption.Shared.Metadata;
using static Acl.Fs.Constant.Cryptography.KeyVaultConstants;

namespace Acl.Fs.Core.UnitTests.Services.Encryption.Shared.Metadata;

public sealed class MetadataServiceTests
{
    [Fact]
    public void PrepareMetadata_SetsCorrectValues()
    {
        const long originalSize = 1000;
        const int bufferSize = 100;

        var dataSize = 2 + NonceSize + 8 + SaltSize;

        var nonce = new byte[NonceSize];
        for (var i = 0; i < NonceSize; i++) nonce[i] = (byte)(i + 1);

        var salt = new byte[SaltSize];

        var metadataBuffer = new byte[bufferSize];
        for (var i = 0; i < bufferSize; i++) metadataBuffer[i] = 0xFF;

        var service = new MetadataService();

        service.PrepareMetadata(nonce, originalSize, salt, metadataBuffer, bufferSize);

        Assert.Equal(1, metadataBuffer[0]);
        Assert.Equal(0, metadataBuffer[1]);

        for (var i = 0; i < NonceSize; i++) Assert.Equal(nonce[i], metadataBuffer[2 + i]);

        var readSize = BinaryPrimitives.ReadInt64LittleEndian(metadataBuffer.AsSpan(2 + NonceSize));
        Assert.Equal(originalSize, readSize);

        for (var i = 0; i < SaltSize; i++) Assert.Equal(salt[i], metadataBuffer[2 + NonceSize + 8 + i]);
        for (var i = dataSize; i < bufferSize; i++) Assert.Equal(0, metadataBuffer[i]);
    }

    [Fact]
    public async Task WriteHeaderAsync_WritesCorrectData()
    {
        const int metadataSize = 54;
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