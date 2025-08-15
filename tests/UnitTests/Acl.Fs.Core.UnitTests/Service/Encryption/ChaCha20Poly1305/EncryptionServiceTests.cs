using System.Security.Cryptography;
using Acl.Fs.Core.Abstractions.Service.Encryption.ChaCha20Poly1305;
using Acl.Fs.Core.Models;
using Acl.Fs.Core.Models.ChaCha20Poly1305;
using Acl.Fs.Core.Service.Encryption.ChaCha20Poly1305;
using Microsoft.Extensions.Logging;
using Moq;
using static Acl.Fs.Constant.Cryptography.CryptoConstants;

namespace Acl.Fs.Core.UnitTests.Service.Encryption.ChaCha20Poly1305;

public sealed class EncryptionServiceTests : IDisposable
{
    private readonly CancellationTokenSource _cancellationTokenSource;
    private readonly EncryptionService _encryptionService;
    private readonly Mock<IEncryptorBase> _mockEncryptorBase;
    private readonly Mock<ILogger<EncryptionService>> _mockLogger;
    private readonly string _tempDirectory;

    public EncryptionServiceTests()
    {
        _mockLogger = new Mock<ILogger<EncryptionService>>();
        _mockEncryptorBase = new Mock<IEncryptorBase>();
        _encryptionService = new EncryptionService(_mockLogger.Object, _mockEncryptorBase.Object);
        _cancellationTokenSource = new CancellationTokenSource();
        _tempDirectory = Path.Combine(Path.GetTempPath(), "AclFsTests", "EncryptionService",
            Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDirectory);
    }

    public void Dispose()
    {
        _cancellationTokenSource.Dispose();

        if (!Directory.Exists(_tempDirectory)) return;
        try
        {
            Directory.Delete(_tempDirectory, true);
        }
        catch
        {
            // Ignore cleanup errors during tests
        }
    }

    private (string sourcePath, string destinationPath) CreateTestPaths(string testName)
    {
        var testId = Guid.NewGuid().ToString("N")[..8];
        var sourcePath = Path.Combine(_tempDirectory, $"{testName}_{testId}_source.txt");
        var destinationPath = Path.Combine(_tempDirectory, $"{testName}_{testId}_destination.enc");

        return (sourcePath, destinationPath);
    }

    [Fact]
    public void Constructor_WithNullLogger_ThrowsArgumentNullException()
    {
        var exception = Assert.Throws<ArgumentNullException>(() =>
            new EncryptionService(null!, _mockEncryptorBase.Object));

        Assert.Equal("logger", exception.ParamName);
    }

    [Fact]
    public void Constructor_WithNullEncryptorBase_ThrowsArgumentNullException()
    {
        var exception = Assert.Throws<ArgumentNullException>(() =>
            new EncryptionService(_mockLogger.Object, null!));

        Assert.Equal("encryptorBase", exception.ParamName);
    }

    [Fact]
    public void Constructor_WithValidParameters_CreatesInstance()
    {
        Assert.NotNull(_encryptionService);
    }

    [Fact]
    public async Task EncryptFileAsync_WithValidParameters_CallsEncryptorBaseWithCorrectParameters()
    {
        var (sourcePath, destinationPath) =
            CreateTestPaths(nameof(EncryptFileAsync_WithValidParameters_CallsEncryptorBaseWithCorrectParameters));
        var transferInstruction = new FileTransferInstruction(sourcePath, destinationPath);

        var encryptionKey = new byte[32];
        RandomNumberGenerator.Fill(encryptionKey);
        var input = new ChaCha20Poly1305EncryptionInput(encryptionKey);

        ReadOnlyMemory<byte> capturedPassword = default;
        ReadOnlyMemory<byte> capturedNonce = default;
        FileTransferInstruction capturedInstruction = null!;

        _mockEncryptorBase
            .Setup(x => x.ExecuteEncryptionProcessAsync(
                It.IsAny<FileTransferInstruction>(),
                It.IsAny<ReadOnlyMemory<byte>>(),
                It.IsAny<ReadOnlyMemory<byte>>(),
                It.IsAny<ILogger>(),
                It.IsAny<CancellationToken>()))
            .Callback<FileTransferInstruction, ReadOnlyMemory<byte>, ReadOnlyMemory<byte>, ILogger, CancellationToken>((
                instruction,
                password, nonce, _, _) =>
            {
                capturedInstruction = instruction;
                capturedPassword = password;
                capturedNonce = nonce;
            })
            .Returns(Task.CompletedTask);

        await _encryptionService.EncryptFileAsync(transferInstruction, input, _cancellationTokenSource.Token);

        _mockEncryptorBase.Verify(x => x.ExecuteEncryptionProcessAsync(
            It.IsAny<FileTransferInstruction>(),
            It.IsAny<ReadOnlyMemory<byte>>(),
            It.IsAny<ReadOnlyMemory<byte>>(),
            _mockLogger.Object,
            _cancellationTokenSource.Token), Times.Once);

        Assert.Equal(sourcePath, capturedInstruction.SourcePath);
        Assert.Equal(destinationPath, capturedInstruction.DestinationPath);
        Assert.Equal(32, capturedPassword.Length);
        Assert.True(capturedPassword.Span.SequenceEqual(encryptionKey));
        Assert.Equal(NonceSize, capturedNonce.Length);
    }

    [Fact]
    public async Task EncryptFileAsync_WithCancelledToken_ThrowsOperationCancelledException()
    {
        var (sourcePath, destinationPath) =
            CreateTestPaths(nameof(EncryptFileAsync_WithCancelledToken_ThrowsOperationCancelledException));
        var transferInstruction = new FileTransferInstruction(sourcePath, destinationPath);

        var encryptionKey = new byte[32];
        RandomNumberGenerator.Fill(encryptionKey);
        var input = new ChaCha20Poly1305EncryptionInput(encryptionKey);

        await _cancellationTokenSource.CancelAsync();

        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            _encryptionService.EncryptFileAsync(transferInstruction, input, _cancellationTokenSource.Token));

        _mockEncryptorBase.Verify(x => x.ExecuteEncryptionProcessAsync(
            It.IsAny<FileTransferInstruction>(),
            It.IsAny<ReadOnlyMemory<byte>>(),
            It.IsAny<ReadOnlyMemory<byte>>(),
            It.IsAny<ILogger>(),
            It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task EncryptFileAsync_WhenEncryptorBaseThrowsException_PropagatesException()
    {
        var (sourcePath, destinationPath) =
            CreateTestPaths(nameof(EncryptFileAsync_WhenEncryptorBaseThrowsException_PropagatesException));
        var transferInstruction = new FileTransferInstruction(sourcePath, destinationPath);

        var encryptionKey = new byte[32];
        RandomNumberGenerator.Fill(encryptionKey);
        var input = new ChaCha20Poly1305EncryptionInput(encryptionKey);

        var expectedException = new InvalidOperationException("Test exception");
        _mockEncryptorBase
            .Setup(x => x.ExecuteEncryptionProcessAsync(
                It.IsAny<FileTransferInstruction>(),
                It.IsAny<ReadOnlyMemory<byte>>(),
                It.IsAny<ReadOnlyMemory<byte>>(),
                It.IsAny<ILogger>(),
                It.IsAny<CancellationToken>()))
            .ThrowsAsync(expectedException);

        var actualException = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _encryptionService.EncryptFileAsync(transferInstruction, input, _cancellationTokenSource.Token));

        Assert.Same(expectedException, actualException);
    }

    [Fact]
    public async Task EncryptFileAsync_GeneratesUniqueNonceForEachCall()
    {
        var (sourcePath, destinationPath) = CreateTestPaths(nameof(EncryptFileAsync_GeneratesUniqueNonceForEachCall));
        var transferInstruction = new FileTransferInstruction(sourcePath, destinationPath);

        var encryptionKey = new byte[32];
        RandomNumberGenerator.Fill(encryptionKey);
        var input = new ChaCha20Poly1305EncryptionInput(encryptionKey);

        var capturedNonces = new List<byte[]>();
        _mockEncryptorBase
            .Setup(x => x.ExecuteEncryptionProcessAsync(
                It.IsAny<FileTransferInstruction>(),
                It.IsAny<ReadOnlyMemory<byte>>(),
                It.IsAny<ReadOnlyMemory<byte>>(),
                It.IsAny<ILogger>(),
                It.IsAny<CancellationToken>()))
            .Callback<FileTransferInstruction, ReadOnlyMemory<byte>, ReadOnlyMemory<byte>, ILogger, CancellationToken>((
                    _, _, nonce,
                    _, _) =>
                capturedNonces.Add(nonce.ToArray()))
            .Returns(Task.CompletedTask);

        await _encryptionService.EncryptFileAsync(transferInstruction, input, _cancellationTokenSource.Token);

        var (sourcePath2, destinationPath2) =
            CreateTestPaths(nameof(EncryptFileAsync_GeneratesUniqueNonceForEachCall) + "_Second");
        var transferInstruction2 = new FileTransferInstruction(sourcePath2, destinationPath2);

        var encryptionKey2 = new byte[32];
        RandomNumberGenerator.Fill(encryptionKey2);

        var input2 = new ChaCha20Poly1305EncryptionInput(encryptionKey2);
        await _encryptionService.EncryptFileAsync(transferInstruction2, input2, _cancellationTokenSource.Token);

        Assert.Equal(2, capturedNonces.Count);
        Assert.All(capturedNonces, nonce => Assert.Equal(NonceSize, nonce.Length));
        Assert.False(capturedNonces[0].SequenceEqual(capturedNonces[1]),
            "Nonces should be unique for each encryption operation");
    }

    [Theory]
    [InlineData("txt")]
    [InlineData("pdf")]
    [InlineData("bin")]
    public async Task EncryptFileAsync_WithDifferentValidPaths_ProcessesSuccessfully(string fileExtension)
    {
        var testId = Guid.NewGuid().ToString("N")[..8];
        var sourcePath = Path.Combine(_tempDirectory, $"source_{testId}.{fileExtension}");
        var destinationPath = Path.Combine(_tempDirectory, $"destination_{testId}.{fileExtension}.encrypted");
        var transferInstruction = new FileTransferInstruction(sourcePath, destinationPath);

        var encryptionKey = new byte[32];
        RandomNumberGenerator.Fill(encryptionKey);
        var input = new ChaCha20Poly1305EncryptionInput(encryptionKey);

        _mockEncryptorBase
            .Setup(x => x.ExecuteEncryptionProcessAsync(
                It.IsAny<FileTransferInstruction>(),
                It.IsAny<ReadOnlyMemory<byte>>(),
                It.IsAny<ReadOnlyMemory<byte>>(),
                It.IsAny<ILogger>(),
                It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        await _encryptionService.EncryptFileAsync(transferInstruction, input, _cancellationTokenSource.Token);

        _mockEncryptorBase.Verify(x => x.ExecuteEncryptionProcessAsync(
            It.Is<FileTransferInstruction>(t => t.SourcePath == sourcePath && t.DestinationPath == destinationPath),
            It.IsAny<ReadOnlyMemory<byte>>(),
            It.IsAny<ReadOnlyMemory<byte>>(),
            It.IsAny<ILogger>(),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task EncryptFileAsync_PassesCorrectKeyToEncryptorBase()
    {
        var (sourcePath, destinationPath) = CreateTestPaths(nameof(EncryptFileAsync_PassesCorrectKeyToEncryptorBase));
        var transferInstruction = new FileTransferInstruction(sourcePath, destinationPath);

        var expectedKey = new byte[32];

        for (var i = 0; i < expectedKey.Length; i++) expectedKey[i] = (byte)(i % 256);

        var input = new ChaCha20Poly1305EncryptionInput(expectedKey);

        ReadOnlyMemory<byte> capturedPassword = default;
        _mockEncryptorBase
            .Setup(x => x.ExecuteEncryptionProcessAsync(
                It.IsAny<FileTransferInstruction>(),
                It.IsAny<ReadOnlyMemory<byte>>(),
                It.IsAny<ReadOnlyMemory<byte>>(),
                It.IsAny<ILogger>(),
                It.IsAny<CancellationToken>()))
            .Callback<FileTransferInstruction, ReadOnlyMemory<byte>, ReadOnlyMemory<byte>, ILogger, CancellationToken>((
                    _, password,
                    _, _, _) =>
                capturedPassword = password)
            .Returns(Task.CompletedTask);

        await _encryptionService.EncryptFileAsync(transferInstruction, input, _cancellationTokenSource.Token);

        Assert.False(capturedPassword.IsEmpty);
        Assert.Equal(32, capturedPassword.Length);
        Assert.True(capturedPassword.Span.SequenceEqual(expectedKey),
            "The encryption key passed to EncryptorBase should match the input key");
    }

    [Fact]
    public async Task EncryptFileAsync_WithLongRunningOperation_CanBeCancelled()
    {
        var (sourcePath, destinationPath) =
            CreateTestPaths(nameof(EncryptFileAsync_WithLongRunningOperation_CanBeCancelled));
        var transferInstruction = new FileTransferInstruction(sourcePath, destinationPath);

        var encryptionKey = new byte[32];
        RandomNumberGenerator.Fill(encryptionKey);

        var input = new ChaCha20Poly1305EncryptionInput(encryptionKey);

        var longRunningTaskCompletionSource = new TaskCompletionSource();
        _mockEncryptorBase
            .Setup(x => x.ExecuteEncryptionProcessAsync(
                It.IsAny<FileTransferInstruction>(),
                It.IsAny<ReadOnlyMemory<byte>>(),
                It.IsAny<ReadOnlyMemory<byte>>(),
                It.IsAny<ILogger>(),
                It.IsAny<CancellationToken>()))
            .Returns(longRunningTaskCompletionSource.Task);

        var encryptionTask = _encryptionService.EncryptFileAsync(
            transferInstruction, input, _cancellationTokenSource.Token);

        await _cancellationTokenSource.CancelAsync();
        longRunningTaskCompletionSource.SetCanceled();

        await Assert.ThrowsAsync<TaskCanceledException>(() => encryptionTask);
    }

    [Fact]
    public async Task EncryptFileAsync_WithPlatformSpecificPaths_HandlesCorrectly()
    {
        var testId = Guid.NewGuid().ToString("N")[..8];
        string sourcePath, destinationPath;

        if (OperatingSystem.IsWindows())
        {
            sourcePath = Path.Combine(_tempDirectory, $"windows_source_{testId}.txt");
            destinationPath = Path.Combine(_tempDirectory, $"windows_destination_{testId}.enc");
        }
        else if (OperatingSystem.IsLinux())
        {
            sourcePath = Path.Combine(_tempDirectory, $"linux_source_{testId}.txt");
            destinationPath = Path.Combine(_tempDirectory, $"linux_destination_{testId}.enc");
        }
        else if (OperatingSystem.IsMacOS())
        {
            sourcePath = Path.Combine(_tempDirectory, $"macos_source_{testId}.txt");
            destinationPath = Path.Combine(_tempDirectory, $"macos_destination_{testId}.enc");
        }
        else
        {
            sourcePath = Path.Combine(_tempDirectory, $"other_source_{testId}.txt");
            destinationPath = Path.Combine(_tempDirectory, $"other_destination_{testId}.enc");
        }

        var transferInstruction = new FileTransferInstruction(sourcePath, destinationPath);

        var encryptionKey = new byte[32];
        RandomNumberGenerator.Fill(encryptionKey);
        var input = new ChaCha20Poly1305EncryptionInput(encryptionKey);

        _mockEncryptorBase
            .Setup(x => x.ExecuteEncryptionProcessAsync(
                It.IsAny<FileTransferInstruction>(),
                It.IsAny<ReadOnlyMemory<byte>>(),
                It.IsAny<ReadOnlyMemory<byte>>(),
                It.IsAny<ILogger>(),
                It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        await _encryptionService.EncryptFileAsync(transferInstruction, input, _cancellationTokenSource.Token);

        _mockEncryptorBase.Verify(x => x.ExecuteEncryptionProcessAsync(
            It.Is<FileTransferInstruction>(t => t.SourcePath == sourcePath && t.DestinationPath == destinationPath),
            It.IsAny<ReadOnlyMemory<byte>>(),
            It.IsAny<ReadOnlyMemory<byte>>(),
            It.IsAny<ILogger>(),
            It.IsAny<CancellationToken>()), Times.Once);

        Assert.Contains(Path.DirectorySeparatorChar.ToString(), sourcePath);
        Assert.Contains(Path.DirectorySeparatorChar.ToString(), destinationPath);
    }
}