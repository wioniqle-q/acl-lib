using System.Security.Cryptography;
using Acl.Fs.Core.Abstractions.Service.Encryption.AesGcm;
using Acl.Fs.Core.Models;
using Acl.Fs.Core.Models.AesGcm;
using Acl.Fs.Core.Service.Encryption.AesGcm;
using Microsoft.Extensions.Logging;
using Moq;

namespace Acl.Fs.Core.UnitTests.Service.Encryption.AesGcm;

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
        _tempDirectory = Path.Combine(Path.GetTempPath(), "AclFsTests", "AesGcmEncryptionService",
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

    [Theory]
    [InlineData(16)]
    [InlineData(24)]
    [InlineData(32)]
    public async Task EncryptFileAsync_WithValidKeySize_CallsEncryptorBaseWithCorrectParameters(int keySize)
    {
        var (sourcePath, destinationPath) =
            CreateTestPaths(
                $"{nameof(EncryptFileAsync_WithValidKeySize_CallsEncryptorBaseWithCorrectParameters)}_{keySize}");
        var transferInstruction = new FileTransferInstruction(sourcePath, destinationPath);

        var encryptionKey = new byte[keySize];
        RandomNumberGenerator.Fill(encryptionKey);
        var input = new AesEncryptionInput(encryptionKey);

        _mockEncryptorBase
            .Setup(x => x.ExecuteEncryptionProcessAsync(
                It.IsAny<FileTransferInstruction>(),
                It.IsAny<byte[]>(),
                It.IsAny<byte[]>(),
                It.IsAny<ILogger>(),
                It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        await _encryptionService.EncryptFileAsync(transferInstruction, input, _cancellationTokenSource.Token);

        _mockEncryptorBase.Verify(x => x.ExecuteEncryptionProcessAsync(
            It.Is<FileTransferInstruction>(t => t.SourcePath == sourcePath && t.DestinationPath == destinationPath),
            It.Is<byte[]>(key => key.Length == keySize && key.SequenceEqual(encryptionKey)),
            It.Is<byte[]>(nonce => nonce.Length == 12),
            _mockLogger.Object,
            _cancellationTokenSource.Token), Times.Once);
    }

    [Fact]
    public async Task EncryptFileAsync_WithCancelledToken_ThrowsOperationCancelledException()
    {
        var (sourcePath, destinationPath) =
            CreateTestPaths(nameof(EncryptFileAsync_WithCancelledToken_ThrowsOperationCancelledException));
        var transferInstruction = new FileTransferInstruction(sourcePath, destinationPath);

        var encryptionKey = new byte[32];
        RandomNumberGenerator.Fill(encryptionKey);
        var input = new AesEncryptionInput(encryptionKey);

        await _cancellationTokenSource.CancelAsync();

        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            _encryptionService.EncryptFileAsync(transferInstruction, input, _cancellationTokenSource.Token));

        _mockEncryptorBase.Verify(x => x.ExecuteEncryptionProcessAsync(
            It.IsAny<FileTransferInstruction>(),
            It.IsAny<byte[]>(),
            It.IsAny<byte[]>(),
            It.IsAny<ILogger>(),
            It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task EncryptFileAsync_WhenEncryptorBaseThrowsException_PropagatesException()
    {
        var (sourcePath, destinationPath) =
            CreateTestPaths(nameof(EncryptFileAsync_WhenEncryptorBaseThrowsException_PropagatesException));
        var transferInstruction = new FileTransferInstruction(sourcePath, destinationPath);

        var encryptionKey = new byte[32]; // AES-256
        RandomNumberGenerator.Fill(encryptionKey);
        var input = new AesEncryptionInput(encryptionKey);

        var expectedException = new InvalidOperationException("Test exception");
        _mockEncryptorBase
            .Setup(x => x.ExecuteEncryptionProcessAsync(
                It.IsAny<FileTransferInstruction>(),
                It.IsAny<byte[]>(),
                It.IsAny<byte[]>(),
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
        var input = new AesEncryptionInput(encryptionKey);

        var capturedNonces = new List<byte[]>();
        _mockEncryptorBase
            .Setup(x => x.ExecuteEncryptionProcessAsync(
                It.IsAny<FileTransferInstruction>(),
                It.IsAny<byte[]>(),
                It.IsAny<byte[]>(),
                It.IsAny<ILogger>(),
                It.IsAny<CancellationToken>()))
            .Callback<FileTransferInstruction, byte[], byte[], ILogger, CancellationToken>((_, _, nonce, _, _) =>
                capturedNonces.Add(nonce.ToArray()))
            .Returns(Task.CompletedTask);

        await _encryptionService.EncryptFileAsync(transferInstruction, input, _cancellationTokenSource.Token);

        var (sourcePath2, destinationPath2) =
            CreateTestPaths(nameof(EncryptFileAsync_GeneratesUniqueNonceForEachCall) + "_Second");
        var transferInstruction2 = new FileTransferInstruction(sourcePath2, destinationPath2);

        var encryptionKey2 = new byte[32];
        RandomNumberGenerator.Fill(encryptionKey2);

        var input2 = new AesEncryptionInput(encryptionKey2);
        await _encryptionService.EncryptFileAsync(transferInstruction2, input2, _cancellationTokenSource.Token);

        Assert.Equal(2, capturedNonces.Count);
        Assert.All(capturedNonces, nonce => Assert.Equal(12, nonce.Length));
        Assert.False(capturedNonces[0].SequenceEqual(capturedNonces[1]),
            "Nonces should be unique for each encryption operation");
    }

    [Theory]
    [InlineData("txt")]
    [InlineData("pdf")]
    [InlineData("bin")]
    [InlineData("docx")]
    public async Task EncryptFileAsync_WithDifferentFileExtensions_ProcessesSuccessfully(string fileExtension)
    {
        var testId = Guid.NewGuid().ToString("N")[..8];
        var sourcePath = Path.Combine(_tempDirectory, $"source_{testId}.{fileExtension}");
        var destinationPath = Path.Combine(_tempDirectory, $"destination_{testId}.{fileExtension}.aes");
        var transferInstruction = new FileTransferInstruction(sourcePath, destinationPath);

        var encryptionKey = new byte[32];
        RandomNumberGenerator.Fill(encryptionKey);
        var input = new AesEncryptionInput(encryptionKey);

        _mockEncryptorBase
            .Setup(x => x.ExecuteEncryptionProcessAsync(
                It.IsAny<FileTransferInstruction>(),
                It.IsAny<byte[]>(),
                It.IsAny<byte[]>(),
                It.IsAny<ILogger>(),
                It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        await _encryptionService.EncryptFileAsync(transferInstruction, input, _cancellationTokenSource.Token);

        _mockEncryptorBase.Verify(x => x.ExecuteEncryptionProcessAsync(
            It.Is<FileTransferInstruction>(t => t.SourcePath == sourcePath && t.DestinationPath == destinationPath),
            It.IsAny<byte[]>(),
            It.IsAny<byte[]>(),
            It.IsAny<ILogger>(),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task EncryptFileAsync_PassesCorrectKeyToEncryptorBase()
    {
        var (sourcePath, destinationPath) = CreateTestPaths(nameof(EncryptFileAsync_PassesCorrectKeyToEncryptorBase));
        var transferInstruction = new FileTransferInstruction(sourcePath, destinationPath);

        var expectedKey = new byte[24];

        for (var i = 0; i < expectedKey.Length; i++) expectedKey[i] = (byte)(i % 256);

        var input = new AesEncryptionInput(expectedKey);

        byte[]? capturedKey = null;
        _mockEncryptorBase
            .Setup(x => x.ExecuteEncryptionProcessAsync(
                It.IsAny<FileTransferInstruction>(),
                It.IsAny<byte[]>(),
                It.IsAny<byte[]>(),
                It.IsAny<ILogger>(),
                It.IsAny<CancellationToken>()))
            .Callback<FileTransferInstruction, byte[], byte[], ILogger, CancellationToken>((_, key, _, _, _) =>
                capturedKey = key.ToArray())
            .Returns(Task.CompletedTask);

        await _encryptionService.EncryptFileAsync(transferInstruction, input, _cancellationTokenSource.Token);

        Assert.NotNull(capturedKey);
        Assert.Equal(24, capturedKey.Length);
        Assert.True(expectedKey.SequenceEqual(capturedKey),
            "The encryption key passed to EncryptorBase should match the input key");
    }

    [Fact]
    public async Task EncryptFileAsync_WithLongRunningOperation_CanBeCancelled()
    {
        var (sourcePath, destinationPath) =
            CreateTestPaths(nameof(EncryptFileAsync_WithLongRunningOperation_CanBeCancelled));
        var transferInstruction = new FileTransferInstruction(sourcePath, destinationPath);

        var encryptionKey = new byte[16]; // AES-128
        RandomNumberGenerator.Fill(encryptionKey);
        var input = new AesEncryptionInput(encryptionKey);

        var longRunningTaskCompletionSource = new TaskCompletionSource();
        _mockEncryptorBase
            .Setup(x => x.ExecuteEncryptionProcessAsync(
                It.IsAny<FileTransferInstruction>(),
                It.IsAny<byte[]>(),
                It.IsAny<byte[]>(),
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
            sourcePath = Path.Combine(_tempDirectory, $"windows_aes_source_{testId}.txt");
            destinationPath = Path.Combine(_tempDirectory, $"windows_aes_destination_{testId}.aes");
        }
        else if (OperatingSystem.IsLinux())
        {
            sourcePath = Path.Combine(_tempDirectory, $"linux_aes_source_{testId}.txt");
            destinationPath = Path.Combine(_tempDirectory, $"linux_aes_destination_{testId}.aes");
        }
        else if (OperatingSystem.IsMacOS())
        {
            sourcePath = Path.Combine(_tempDirectory, $"macos_aes_source_{testId}.txt");
            destinationPath = Path.Combine(_tempDirectory, $"macos_aes_destination_{testId}.aes");
        }
        else
        {
            sourcePath = Path.Combine(_tempDirectory, $"other_aes_source_{testId}.txt");
            destinationPath = Path.Combine(_tempDirectory, $"other_aes_destination_{testId}.aes");
        }

        var transferInstruction = new FileTransferInstruction(sourcePath, destinationPath);

        var encryptionKey = new byte[32];
        RandomNumberGenerator.Fill(encryptionKey);
        var input = new AesEncryptionInput(encryptionKey);

        _mockEncryptorBase
            .Setup(x => x.ExecuteEncryptionProcessAsync(
                It.IsAny<FileTransferInstruction>(),
                It.IsAny<byte[]>(),
                It.IsAny<byte[]>(),
                It.IsAny<ILogger>(),
                It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        await _encryptionService.EncryptFileAsync(transferInstruction, input, _cancellationTokenSource.Token);

        _mockEncryptorBase.Verify(x => x.ExecuteEncryptionProcessAsync(
            It.Is<FileTransferInstruction>(t => t.SourcePath == sourcePath && t.DestinationPath == destinationPath),
            It.IsAny<byte[]>(),
            It.IsAny<byte[]>(),
            It.IsAny<ILogger>(),
            It.IsAny<CancellationToken>()), Times.Once);

        Assert.Contains(Path.DirectorySeparatorChar.ToString(), sourcePath);
        Assert.Contains(Path.DirectorySeparatorChar.ToString(), destinationPath);
    }

    [Fact]
    public async Task EncryptFileAsync_WithAes128Key_ProcessesCorrectly()
    {
        var (sourcePath, destinationPath) = CreateTestPaths(nameof(EncryptFileAsync_WithAes128Key_ProcessesCorrectly));
        var transferInstruction = new FileTransferInstruction(sourcePath, destinationPath);

        var encryptionKey = new byte[16];
        RandomNumberGenerator.Fill(encryptionKey);
        var input = new AesEncryptionInput(encryptionKey);

        _mockEncryptorBase
            .Setup(x => x.ExecuteEncryptionProcessAsync(
                It.IsAny<FileTransferInstruction>(),
                It.IsAny<byte[]>(),
                It.IsAny<byte[]>(),
                It.IsAny<ILogger>(),
                It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        await _encryptionService.EncryptFileAsync(transferInstruction, input, _cancellationTokenSource.Token);

        _mockEncryptorBase.Verify(x => x.ExecuteEncryptionProcessAsync(
            It.IsAny<FileTransferInstruction>(),
            It.Is<byte[]>(key => key.Length == 16),
            It.IsAny<byte[]>(),
            It.IsAny<ILogger>(),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task EncryptFileAsync_WithAes192Key_ProcessesCorrectly()
    {
        var (sourcePath, destinationPath) = CreateTestPaths(nameof(EncryptFileAsync_WithAes192Key_ProcessesCorrectly));
        var transferInstruction = new FileTransferInstruction(sourcePath, destinationPath);

        var encryptionKey = new byte[24];
        RandomNumberGenerator.Fill(encryptionKey);
        var input = new AesEncryptionInput(encryptionKey);

        _mockEncryptorBase
            .Setup(x => x.ExecuteEncryptionProcessAsync(
                It.IsAny<FileTransferInstruction>(),
                It.IsAny<byte[]>(),
                It.IsAny<byte[]>(),
                It.IsAny<ILogger>(),
                It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        await _encryptionService.EncryptFileAsync(transferInstruction, input, _cancellationTokenSource.Token);

        _mockEncryptorBase.Verify(x => x.ExecuteEncryptionProcessAsync(
            It.IsAny<FileTransferInstruction>(),
            It.Is<byte[]>(key => key.Length == 24),
            It.IsAny<byte[]>(),
            It.IsAny<ILogger>(),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task EncryptFileAsync_WithAes256Key_ProcessesCorrectly()
    {
        var (sourcePath, destinationPath) = CreateTestPaths(nameof(EncryptFileAsync_WithAes256Key_ProcessesCorrectly));
        var transferInstruction = new FileTransferInstruction(sourcePath, destinationPath);

        var encryptionKey = new byte[32];
        RandomNumberGenerator.Fill(encryptionKey);
        var input = new AesEncryptionInput(encryptionKey);

        _mockEncryptorBase
            .Setup(x => x.ExecuteEncryptionProcessAsync(
                It.IsAny<FileTransferInstruction>(),
                It.IsAny<byte[]>(),
                It.IsAny<byte[]>(),
                It.IsAny<ILogger>(),
                It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        await _encryptionService.EncryptFileAsync(transferInstruction, input, _cancellationTokenSource.Token);

        _mockEncryptorBase.Verify(x => x.ExecuteEncryptionProcessAsync(
            It.IsAny<FileTransferInstruction>(),
            It.Is<byte[]>(key => key.Length == 32),
            It.IsAny<byte[]>(),
            It.IsAny<ILogger>(),
            It.IsAny<CancellationToken>()), Times.Once);
    }
}