using Acl.Fs.Core.Abstractions;
using Acl.Fs.Core.Abstractions.Service.Decryption.Shared.Audit;
using Acl.Fs.Core.Abstractions.Service.Decryption.Shared.Block;
using Acl.Fs.Core.Abstractions.Service.Decryption.Shared.Processor;
using Acl.Fs.Core.Abstractions.Service.Decryption.Shared.Validation;
using Acl.Fs.Core.Service.Decryption.Shared.Processor;
using Acl.Fs.Core.Service.Decryption.Shared.Validation;
using Moq;
using static Acl.Fs.Constant.Cryptography.CryptoConstants;

namespace Acl.Fs.Core.UnitTests.Service.Decryption.Shared.Processor;

public sealed class BlockProcessorTests
{
    private readonly Mock<IAlignmentPolicy> _alignmentPolicyMock;
    private readonly Mock<IAuditService> _auditServiceMock;
    private readonly BlockProcessor<object> _blockProcessor;
    private readonly Mock<IBlockReader> _blockReaderMock;
    private readonly Mock<IBlockValidator> _blockValidatorMock;
    private readonly Mock<ICryptoProvider<object>> _cryptoProviderMock;

    public BlockProcessorTests()
    {
        _alignmentPolicyMock = new Mock<IAlignmentPolicy>();
        _cryptoProviderMock = new Mock<ICryptoProvider<object>>();
        _blockValidatorMock = new Mock<IBlockValidator>();
        _blockReaderMock = new Mock<IBlockReader>();
        _auditServiceMock = new Mock<IAuditService>();
        _blockProcessor = new BlockProcessor<object>(
            _alignmentPolicyMock.Object,
            _cryptoProviderMock.Object,
            _blockValidatorMock.Object,
            _blockReaderMock.Object,
            _auditServiceMock.Object
        );
    }

    [Fact]
    public async Task ProcessBlockAsync_NormalBlock_WritesCorrectly()
    {
        const int bytesRead = 100;
        const long blockIndex = 0;
        const long processedBytes = 0;
        const long originalSize = 200;

        var destinationStream = new MemoryStream();
        var cryptoAlgorithm = new object();
        var buffer = new byte[100];
        var plaintext = new byte[100];
        var alignedBuffer = new byte[100];
        var tag = new byte[16];
        var chunkNonce = new byte[12];
        var salt = new byte[32];
        var cancellationToken = CancellationToken.None;

        _alignmentPolicyMock.Setup(p => p.CalculateProcessingSize(bytesRead, false)).Returns(100);
        _cryptoProviderMock.Setup(p => p.DecryptBlock(
            cryptoAlgorithm,
            buffer,
            plaintext,
            tag,
            chunkNonce,
            salt,
            100,
            blockIndex
        )).Callback(() => Array.Fill(plaintext, (byte)'a'));
        _blockValidatorMock.Setup(v => v.ValidateBlockWriteParameters(
            bytesRead,
            originalSize,
            processedBytes,
            100,
            plaintext.Length
        )).Verifiable();

        await _blockProcessor.ProcessBlockAsync(
            destinationStream,
            cryptoAlgorithm,
            buffer,
            plaintext,
            alignedBuffer,
            tag,
            chunkNonce,
            salt,
            bytesRead,
            blockIndex,
            processedBytes,
            originalSize,
            NonceSize,
            cancellationToken
        );

        Assert.Equal(100, destinationStream.Length);

        var writtenData = destinationStream.ToArray();
        Assert.All(writtenData, b => Assert.Equal((byte)'a', b));

        _blockValidatorMock.Verify();
    }

    [Fact]
    public async Task ProcessBlockAsync_LastBlock_WritesAndSetsLength()
    {
        const int bytesRead = 100;
        const long blockIndex = 1;
        const long processedBytes = 100;
        const long originalSize = 150;

        var destinationStream = new MemoryStream();
        destinationStream.Write(new byte[100], 0, 100);
        destinationStream.Position = 100;

        var cryptoAlgorithm = new object();
        var buffer = new byte[100];
        var plaintext = new byte[100];
        var alignedBuffer = new byte[100];
        var tag = new byte[16];
        var chunkNonce = new byte[12];
        var salt = new byte[32];

        var cancellationToken = CancellationToken.None;

        _alignmentPolicyMock.Setup(p => p.CalculateProcessingSize(100, true)).Returns(100);
        _alignmentPolicyMock.Setup(p => p.CalculateProcessingSize(50, true)).Returns(64);
        _cryptoProviderMock.Setup(p => p.DecryptBlock(
            cryptoAlgorithm,
            buffer,
            plaintext,
            tag,
            chunkNonce,
            salt,
            100,
            blockIndex
        )).Callback(() => Array.Fill(plaintext, (byte)'b', 0, 50));
        _blockValidatorMock.Setup(v => v.ValidateBlockWriteParameters(
            100,
            150,
            100,
            100,
            100
        )).Verifiable();

        await _blockProcessor.ProcessBlockAsync(
            destinationStream,
            cryptoAlgorithm,
            buffer,
            plaintext,
            alignedBuffer,
            tag,
            chunkNonce,
            salt,
            bytesRead,
            blockIndex,
            processedBytes,
            originalSize,
            NonceSize,
            cancellationToken
        );

        destinationStream.Position = 0;

        var data = destinationStream.ToArray();
        Assert.Equal(150, destinationStream.Length);

        Assert.All(data.Take(100), b => Assert.Equal(0, b));
        Assert.All(data.Skip(100).Take(50), b => Assert.Equal((byte)'b', b));
    }

    [Fact]
    public async Task ProcessBlockAsync_BlockSizeExceedsPlaintext_ThrowsException()
    {
        const int bytesRead = 100;
        const long blockIndex = 0;
        const long processedBytes = 0;
        const long originalSize = 200;

        var destinationStream = new MemoryStream();
        var cryptoAlgorithm = new object();
        var buffer = new byte[100];
        var plaintext = new byte[100];
        var alignedBuffer = new byte[100];
        var tag = new byte[16];
        var chunkNonce = new byte[12];
        var salt = new byte[32];

        var cancellationToken = CancellationToken.None;

        var blockValidator = new BlockValidator();

        var blockProcessor = new BlockProcessor<object>(
            _alignmentPolicyMock.Object,
            _cryptoProviderMock.Object,
            blockValidator,
            _blockReaderMock.Object,
            _auditServiceMock.Object
        );

        _alignmentPolicyMock.Setup(p => p.CalculateProcessingSize(bytesRead, false)).Returns(101);
        _cryptoProviderMock.Setup(p => p.DecryptBlock(
            cryptoAlgorithm,
            buffer,
            plaintext,
            tag,
            chunkNonce,
            salt,
            101,
            blockIndex
        )).Callback(() => { });

        await Assert.ThrowsAsync<InvalidOperationException>(() => blockProcessor.ProcessBlockAsync(
            destinationStream,
            cryptoAlgorithm,
            buffer,
            plaintext,
            alignedBuffer,
            tag,
            chunkNonce,
            salt,
            bytesRead,
            blockIndex,
            processedBytes,
            originalSize,
            NonceSize,
            cancellationToken
        ));
    }
}