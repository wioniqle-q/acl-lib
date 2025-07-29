using Acl.Fs.Core.Abstractions.Service.Encryption.Shared.Audit;
using Acl.Fs.Core.Service.Encryption.Shared.Validation;
using Moq;

namespace Acl.Fs.Core.UnitTests.Service.Encryption.Shared.Validation;

public sealed class ValidationServiceTests
{
    private readonly Mock<IAuditService> _mockAuditService;
    private readonly ValidationService _validationService;

    public ValidationServiceTests()
    {
        _mockAuditService = new Mock<IAuditService>();
        _validationService = new ValidationService(_mockAuditService.Object);
    }

    [Fact]
    public async Task ValidateFileReadConsistencyAsync_WhenBytesMatchStreamLength_DoesNotThrow()
    {
        var testData = "Hello"u8.ToArray();

        using var stream = new MemoryStream(testData);

        var totalBytesRead = testData.Length;
        var cancellationToken = CancellationToken.None;

        await _validationService.ValidateFileReadConsistencyAsync(totalBytesRead, stream, cancellationToken);

        _mockAuditService.Verify(
            x => x.AuditFileReadConsistency(It.IsAny<long>(), It.IsAny<System.IO.Stream>(),
                It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task
        ValidateFileReadConsistencyAsync_WhenBytesReadLessThanStreamLength_ThrowsInvalidOperationException()
    {
        const long totalBytesRead = 3;
        var testData = "ABCDE"u8.ToArray();

        using var stream = new MemoryStream(testData);
        var cancellationToken = CancellationToken.None;

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _validationService.ValidateFileReadConsistencyAsync(totalBytesRead, stream, cancellationToken));

        _mockAuditService.Verify(
            x => x.AuditFileReadConsistency(totalBytesRead, It.IsAny<System.IO.Stream>(), cancellationToken),
            Times.Once);
    }

    [Fact]
    public async Task
        ValidateFileReadConsistencyAsync_WhenBytesReadMoreThanStreamLength_ThrowsInvalidOperationException()
    {
        const int totalBytesRead = 5;
        var testData = "012"u8.ToArray();

        using var stream = new MemoryStream(testData);
        var cancellationToken = CancellationToken.None;

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _validationService.ValidateFileReadConsistencyAsync(totalBytesRead, stream, cancellationToken));

        _mockAuditService.Verify(
            x => x.AuditFileReadConsistency(totalBytesRead, It.IsAny<System.IO.Stream>(), cancellationToken),
            Times.Once);
    }

    [Fact]
    public async Task ValidateFileReadConsistencyAsync_WithEmptyStream_WhenZeroBytesRead_DoesNotThrow()
    {
        const long totalBytesRead = 0L;

        using var stream = new MemoryStream();
        var cancellationToken = CancellationToken.None;

        await _validationService.ValidateFileReadConsistencyAsync(totalBytesRead, stream, cancellationToken);

        _mockAuditService.Verify(
            x => x.AuditFileReadConsistency(It.IsAny<long>(), It.IsAny<System.IO.Stream>(),
                It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task ValidateFileReadConsistencyAsync_WithCanceledToken_ThrowsOperationCanceledException()
    {
        const long totalBytesRead = 1L;

        var testData = new byte[] { 0xFF, 0xFE, 0xFD };
        var cancellationToken = new CancellationToken(true);

        using var stream = new MemoryStream(testData);

        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            _validationService.ValidateFileReadConsistencyAsync(totalBytesRead, stream, cancellationToken));

        _mockAuditService.Verify(
            x => x.AuditFileReadConsistency(It.IsAny<long>(), It.IsAny<System.IO.Stream>(),
                It.IsAny<CancellationToken>()),
            Times.Never);
    }
}