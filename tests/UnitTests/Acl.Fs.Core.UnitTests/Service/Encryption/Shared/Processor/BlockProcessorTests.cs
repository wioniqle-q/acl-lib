using Acl.Fs.Core.Abstractions;
using Acl.Fs.Core.Abstractions.Service.Encryption.Shared.Audit;
using Acl.Fs.Core.Abstractions.Service.Encryption.Shared.Processor;
using Acl.Fs.Core.Abstractions.Service.Encryption.Shared.Validation;
using Acl.Fs.Core.Service.Encryption.Shared.Buffer;
using Acl.Fs.Core.Service.Encryption.Shared.Processor;
using Moq;
using static Acl.Fs.Constant.Cryptography.CryptoConstants;
using static Acl.Fs.Constant.Storage.StorageConstants;

namespace Acl.Fs.Core.UnitTests.Service.Encryption.Shared.Processor;

public sealed class BlockProcessorTests
{
    [Fact]
    public async Task ProcessBlockAsync_WhenCancellationRequested_ThrowsOperationCanceledException()
    {
        var cryptoProviderMock = new Mock<ICryptoProvider<object>>();
        var alignmentPolicyMock = new Mock<IAlignmentPolicy>();
        var auditServiceMock = new Mock<IAuditService>();
        var validationServiceMock = new Mock<IValidationService>();
        var blockProcessor = new BlockProcessor<object>(cryptoProviderMock.Object, alignmentPolicyMock.Object,
            auditServiceMock.Object, validationServiceMock.Object);

        var destinationStream = new MemoryStream();
        var cryptoAlgorithm = new object();
        var bufferManager = new BufferManager(SectorSize, NonceSize);

        var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAsync<OperationCanceledException>(async () =>
            await blockProcessor.ProcessBlockAsync(destinationStream, cryptoAlgorithm, bufferManager, BufferSize, 0, 1,
                SectorSize, cts.Token));

        alignmentPolicyMock.Verify(m => m.CalculateProcessingSize(It.IsAny<int>(), It.IsAny<bool>()), Times.Never());
        bufferManager.Dispose();
    }

    [Theory]
    [InlineData(0, 1, BufferSize, true)]
    [InlineData(0, 2, 500, true)]
    [InlineData(0, 2, BufferSize, false)]
    public async Task ProcessBlockAsync_CalculatesIsLastBlockCorrectly(int blockIndex, int totalBlocks, int bytesRead,
        bool expectedIsLastBlock)
    {
        var cryptoProviderMock = new Mock<ICryptoProvider<object>>();
        var alignmentPolicyMock = new Mock<IAlignmentPolicy>();
        var auditServiceMock = new Mock<IAuditService>();
        var validationServiceMock = new Mock<IValidationService>();
        var blockProcessor = new BlockProcessor<object>(cryptoProviderMock.Object, alignmentPolicyMock.Object,
            auditServiceMock.Object, validationServiceMock.Object);

        var destinationStream = new MemoryStream();
        var cryptoAlgorithm = new object();
        var bufferManager = new BufferManager(SectorSize, NonceSize);

        alignmentPolicyMock.Setup(m => m.CalculateProcessingSize(bytesRead, expectedIsLastBlock)).Returns(bytesRead);

        await blockProcessor.ProcessBlockAsync(destinationStream, cryptoAlgorithm, bufferManager, bytesRead, blockIndex,
            totalBlocks, SectorSize, CancellationToken.None);

        alignmentPolicyMock.Verify(m => m.CalculateProcessingSize(bytesRead, expectedIsLastBlock), Times.Once());
        bufferManager.Dispose();
    }

    [Fact]
    public async Task ProcessBlockAsync_WhenBytesReadLessThanAlignedSize_ClearsBuffer()
    {
        const int bytesRead = 500;

        var cryptoProviderMock = new Mock<ICryptoProvider<object>>();
        var alignmentPolicyMock = new Mock<IAlignmentPolicy>();
        var auditServiceMock = new Mock<IAuditService>();
        var validationServiceMock = new Mock<IValidationService>();
        var blockProcessor = new BlockProcessor<object>(cryptoProviderMock.Object, alignmentPolicyMock.Object,
            auditServiceMock.Object, validationServiceMock.Object);

        var destinationStream = new MemoryStream();
        var cryptoAlgorithm = new object();
        var bufferManager = new BufferManager(SectorSize, NonceSize);

        alignmentPolicyMock.Setup(m => m.CalculateProcessingSize(bytesRead, It.IsAny<bool>())).Returns(BufferSize);
        Array.Fill(bufferManager.Buffer, (byte)1);

        await blockProcessor.ProcessBlockAsync(destinationStream, cryptoAlgorithm, bufferManager, bytesRead, 0, 1,
            SectorSize, CancellationToken.None);

        for (var i = bytesRead; i < BufferSize; i++)
            Assert.Equal(0, bufferManager.Buffer[i]);

        bufferManager.Dispose();
    }

    [Fact]
    public async Task ProcessBlockAsync_WhenExceptionOccurs_AuditsFailure()
    {
        var cryptoProviderMock = new Mock<ICryptoProvider<object>>();
        var alignmentPolicyMock = new Mock<IAlignmentPolicy>();
        var auditServiceMock = new Mock<IAuditService>();
        var validationServiceMock = new Mock<IValidationService>();
        var blockProcessor = new BlockProcessor<object>(cryptoProviderMock.Object, alignmentPolicyMock.Object,
            auditServiceMock.Object, validationServiceMock.Object);

        var destinationStream = new MemoryStream();
        var cryptoAlgorithm = new object();
        var bufferManager = new BufferManager(SectorSize, NonceSize);

        cryptoProviderMock.Setup(m => m.EncryptBlock(It.IsAny<object>(), It.IsAny<byte[]>(), It.IsAny<byte[]>(),
                It.IsAny<byte[]>(), It.IsAny<byte[]>(), It.IsAny<int>(), It.IsAny<long>(), It.IsAny<byte[]>()))
            .Throws(new InvalidOperationException("Encryption failed"));

        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await blockProcessor.ProcessBlockAsync(destinationStream, cryptoAlgorithm, bufferManager, BufferSize, 0, 1,
                SectorSize, CancellationToken.None));

        auditServiceMock.Verify(m => m.AuditBlockEncryptionFailed(0, It.IsAny<Exception>(), CancellationToken.None),
            Times.Once());
        bufferManager.Dispose();
    }

    [Theory]
    [InlineData(0, 1, BufferSize, BufferSize)]
    [InlineData(0, 1, 500, 500)]
    [InlineData(0, 2, BufferSize, BufferSize)]
    public async Task ReadBlockAsync_ReturnsCorrectBytesRead(int blockIndex, int totalBlocks, int availableBytes,
        int expectedBytes)
    {
        var cryptoProviderMock = new Mock<ICryptoProvider<object>>();
        var alignmentPolicyMock = new Mock<IAlignmentPolicy>();
        var auditServiceMock = new Mock<IAuditService>();
        var validationServiceMock = new Mock<IValidationService>();
        var blockProcessor = new BlockProcessor<object>(cryptoProviderMock.Object, alignmentPolicyMock.Object,
            auditServiceMock.Object, validationServiceMock.Object);

        var sourceStream = new MemoryStream(new byte[availableBytes]);
        var buffer = new byte[BufferSize];

        var bytesRead =
            await blockProcessor.ReadBlockAsync(sourceStream, buffer, blockIndex, totalBlocks, CancellationToken.None);

        Assert.Equal(expectedBytes, bytesRead);
    }

    [Fact]
    public async Task ReadBlockAsync_WhenNotLastBlockAndInsufficientData_ReturnsZero()
    {
        var cryptoProviderMock = new Mock<ICryptoProvider<object>>();
        var alignmentPolicyMock = new Mock<IAlignmentPolicy>();
        var auditServiceMock = new Mock<IAuditService>();
        var validationServiceMock = new Mock<IValidationService>();
        var blockProcessor = new BlockProcessor<object>(cryptoProviderMock.Object, alignmentPolicyMock.Object,
            auditServiceMock.Object, validationServiceMock.Object);

        var sourceStream = new MemoryStream(new byte[500]);
        var buffer = new byte[BufferSize];

        var bytesRead = await blockProcessor.ReadBlockAsync(sourceStream, buffer, 0, 2, CancellationToken.None);

        Assert.Equal(0, bytesRead);
    }

    [Fact]
    public async Task WriteEncryptedBlockAsync_WhenMetadataBufferSizeNotSectorSize_WritesTagDirectly()
    {
        var cryptoProviderMock = new Mock<ICryptoProvider<object>>();
        var alignmentPolicyMock = new Mock<IAlignmentPolicy>();
        var auditServiceMock = new Mock<IAuditService>();
        var validationServiceMock = new Mock<IValidationService>();
        var blockProcessor = new BlockProcessor<object>(cryptoProviderMock.Object, alignmentPolicyMock.Object,
            auditServiceMock.Object, validationServiceMock.Object);

        var destinationStream = new MemoryStream();
        var metadataBuffer = new byte[HmacKeySize];
        var tag = new byte[TagSize];
        var ciphertext = new byte[BufferSize];

        Array.Fill(tag, (byte)1);
        Array.Fill(ciphertext, (byte)2);

        await blockProcessor.WriteEncryptedBlockAsync(destinationStream, metadataBuffer, tag, ciphertext, BufferSize,
            HmacKeySize, CancellationToken.None);

        var writtenData = destinationStream.ToArray();

        Assert.Equal(TagSize + BufferSize, writtenData.Length);
        Assert.Equal(tag, writtenData.AsSpan(0, TagSize).ToArray());
        Assert.Equal(ciphertext, writtenData.AsSpan(TagSize, BufferSize).ToArray());
    }
}