using System.Security.Cryptography;
using Acl.Fs.Core.Abstractions.Service.Decryption.ChaCha20Poly1305;
using Acl.Fs.Core.Models;
using Acl.Fs.Core.Models.ChaCha20Poly1305;
using Acl.Fs.Core.Service.Decryption.ChaCha20Poly1305;
using Microsoft.Extensions.Logging;
using Moq;

namespace Acl.Fs.Core.UnitTests.Service.Decryption.ChaCha20Poly1305;

public sealed class DecryptionServiceTests : IDisposable
{
    private readonly CancellationTokenSource _cancellationTokenSource;
    private readonly DecryptionService _decryptionService;
    private readonly Mock<IDecryptorBase> _mockDecryptorBase;
    private readonly Mock<ILogger<DecryptionService>> _mockLogger;
    private readonly string _tempDirectory;

    public DecryptionServiceTests()
    {
        _mockLogger = new Mock<ILogger<DecryptionService>>();
        _mockDecryptorBase = new Mock<IDecryptorBase>();
        _decryptionService = new DecryptionService(_mockLogger.Object, _mockDecryptorBase.Object);
        _cancellationTokenSource = new CancellationTokenSource();
        _tempDirectory = Path.Combine(Path.GetTempPath(), "AclFsTests", "ChaCha20Poly1305DecryptionService",
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
        var sourcePath = Path.Combine(_tempDirectory, $"{testName}_{testId}_encrypted.enc");
        var destinationPath = Path.Combine(_tempDirectory, $"{testName}_{testId}_decrypted.txt");
        return (sourcePath, destinationPath);
    }

    [Fact]
    public void Constructor_WithNullLogger_ThrowsArgumentNullException()
    {
        var exception = Assert.Throws<ArgumentNullException>(() =>
            new DecryptionService(null!, _mockDecryptorBase.Object));

        Assert.Equal("logger", exception.ParamName);
    }

    [Fact]
    public void Constructor_WithNullDecryptorBase_ThrowsArgumentNullException()
    {
        var exception = Assert.Throws<ArgumentNullException>(() =>
            new DecryptionService(_mockLogger.Object, null!));

        Assert.Equal("decryptorBase", exception.ParamName);
    }

    [Fact]
    public void Constructor_WithValidParameters_CreatesInstance()
    {
        Assert.NotNull(_decryptionService);
    }

    [Fact]
    public async Task DecryptFileAsync_WithValidParameters_CallsDecryptorBaseWithCorrectParameters()
    {
        var (sourcePath, destinationPath) =
            CreateTestPaths(nameof(DecryptFileAsync_WithValidParameters_CallsDecryptorBaseWithCorrectParameters));
        var transferInstruction = new FileTransferInstruction(sourcePath, destinationPath);

        var decryptionKey = new byte[32];
        RandomNumberGenerator.Fill(decryptionKey);
        var input = new ChaCha20Poly1305DecryptionInput(decryptionKey);

        ReadOnlyMemory<byte> capturedPassword = default;
        FileTransferInstruction capturedInstruction = null!;

        _mockDecryptorBase
            .Setup(x => x.ExecuteDecryptionProcessAsync(
                It.IsAny<FileTransferInstruction>(),
                It.IsAny<ReadOnlyMemory<byte>>(),
                It.IsAny<ILogger>(),
                It.IsAny<CancellationToken>()))
            .Callback<FileTransferInstruction, ReadOnlyMemory<byte>, ILogger, CancellationToken>((instruction, password,
                _, _) =>
            {
                capturedInstruction = instruction;
                capturedPassword = password;
            })
            .Returns(Task.CompletedTask);

        await _decryptionService.DecryptFileAsync(transferInstruction, input, _cancellationTokenSource.Token);

        _mockDecryptorBase.Verify(x => x.ExecuteDecryptionProcessAsync(
            It.IsAny<FileTransferInstruction>(),
            It.IsAny<ReadOnlyMemory<byte>>(),
            _mockLogger.Object,
            _cancellationTokenSource.Token), Times.Once);

        Assert.Equal(sourcePath, capturedInstruction.SourcePath);
        Assert.Equal(destinationPath, capturedInstruction.DestinationPath);
        Assert.Equal(32, capturedPassword.Length);
        Assert.True(capturedPassword.Span.SequenceEqual(decryptionKey));
    }

    [Fact]
    public async Task DecryptFileAsync_WithCancelledToken_ThrowsOperationCancelledException()
    {
        var (sourcePath, destinationPath) =
            CreateTestPaths(nameof(DecryptFileAsync_WithCancelledToken_ThrowsOperationCancelledException));
        var transferInstruction = new FileTransferInstruction(sourcePath, destinationPath);

        var decryptionKey = new byte[32];
        RandomNumberGenerator.Fill(decryptionKey);
        var input = new ChaCha20Poly1305DecryptionInput(decryptionKey);

        await _cancellationTokenSource.CancelAsync();

        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            _decryptionService.DecryptFileAsync(transferInstruction, input, _cancellationTokenSource.Token));

        _mockDecryptorBase.Verify(x => x.ExecuteDecryptionProcessAsync(
            It.IsAny<FileTransferInstruction>(),
            It.IsAny<ReadOnlyMemory<byte>>(),
            It.IsAny<ILogger>(),
            It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task DecryptFileAsync_WhenDecryptorBaseThrowsException_PropagatesException()
    {
        var (sourcePath, destinationPath) =
            CreateTestPaths(nameof(DecryptFileAsync_WhenDecryptorBaseThrowsException_PropagatesException));
        var transferInstruction = new FileTransferInstruction(sourcePath, destinationPath);

        var decryptionKey = new byte[32];
        RandomNumberGenerator.Fill(decryptionKey);
        var input = new ChaCha20Poly1305DecryptionInput(decryptionKey);

        var expectedException = new InvalidOperationException("Decryption failed");
        _mockDecryptorBase
            .Setup(x => x.ExecuteDecryptionProcessAsync(
                It.IsAny<FileTransferInstruction>(),
                It.IsAny<ReadOnlyMemory<byte>>(),
                It.IsAny<ILogger>(),
                It.IsAny<CancellationToken>()))
            .ThrowsAsync(expectedException);

        var actualException = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _decryptionService.DecryptFileAsync(transferInstruction, input, _cancellationTokenSource.Token));

        Assert.Same(expectedException, actualException);
    }

    [Fact]
    public async Task DecryptFileAsync_PassesCorrectKeyToDecryptorBase()
    {
        var (sourcePath, destinationPath) = CreateTestPaths(nameof(DecryptFileAsync_PassesCorrectKeyToDecryptorBase));
        var transferInstruction = new FileTransferInstruction(sourcePath, destinationPath);

        var expectedKey = new byte[32];
        for (var i = 0; i < expectedKey.Length; i++) expectedKey[i] = (byte)(i % 256);

        var input = new ChaCha20Poly1305DecryptionInput(expectedKey);

        ReadOnlyMemory<byte> capturedPassword = default;
        _mockDecryptorBase
            .Setup(x => x.ExecuteDecryptionProcessAsync(
                It.IsAny<FileTransferInstruction>(),
                It.IsAny<ReadOnlyMemory<byte>>(),
                It.IsAny<ILogger>(),
                It.IsAny<CancellationToken>()))
            .Callback<FileTransferInstruction, ReadOnlyMemory<byte>, ILogger, CancellationToken>((_, password, _, _) =>
                capturedPassword = password)
            .Returns(Task.CompletedTask);

        await _decryptionService.DecryptFileAsync(transferInstruction, input, _cancellationTokenSource.Token);

        Assert.False(capturedPassword.IsEmpty);
        Assert.Equal(32, capturedPassword.Length);
        Assert.True(capturedPassword.Span.SequenceEqual(expectedKey),
            "The decryption key passed to DecryptorBase should match the input key");
    }

    [Fact]
    public async Task DecryptFileAsync_WithLongRunningOperation_CanBeCancelled()
    {
        var (sourcePath, destinationPath) =
            CreateTestPaths(nameof(DecryptFileAsync_WithLongRunningOperation_CanBeCancelled));
        var transferInstruction = new FileTransferInstruction(sourcePath, destinationPath);

        var decryptionKey = new byte[32];
        RandomNumberGenerator.Fill(decryptionKey);
        var input = new ChaCha20Poly1305DecryptionInput(decryptionKey);

        var longRunningTaskCompletionSource = new TaskCompletionSource();
        _mockDecryptorBase
            .Setup(x => x.ExecuteDecryptionProcessAsync(
                It.IsAny<FileTransferInstruction>(),
                It.IsAny<ReadOnlyMemory<byte>>(),
                It.IsAny<ILogger>(),
                It.IsAny<CancellationToken>()))
            .Returns(longRunningTaskCompletionSource.Task);

        var decryptionTask = _decryptionService.DecryptFileAsync(
            transferInstruction, input, _cancellationTokenSource.Token);

        await _cancellationTokenSource.CancelAsync();
        longRunningTaskCompletionSource.SetCanceled();

        await Assert.ThrowsAsync<TaskCanceledException>(() => decryptionTask);
    }

    [Theory]
    [InlineData("enc")]
    [InlineData("encrypted")]
    [InlineData("chacha")]
    public async Task DecryptFileAsync_WithDifferentEncryptedFileExtensions_ProcessesSuccessfully(string fileExtension)
    {
        var testId = Guid.NewGuid().ToString("N")[..8];
        var sourcePath = Path.Combine(_tempDirectory, $"encrypted_{testId}.{fileExtension}");
        var destinationPath = Path.Combine(_tempDirectory, $"decrypted_{testId}.txt");
        var transferInstruction = new FileTransferInstruction(sourcePath, destinationPath);

        var decryptionKey = new byte[32];
        RandomNumberGenerator.Fill(decryptionKey);
        var input = new ChaCha20Poly1305DecryptionInput(decryptionKey);

        _mockDecryptorBase
            .Setup(x => x.ExecuteDecryptionProcessAsync(
                It.IsAny<FileTransferInstruction>(),
                It.IsAny<ReadOnlyMemory<byte>>(),
                It.IsAny<ILogger>(),
                It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        await _decryptionService.DecryptFileAsync(transferInstruction, input, _cancellationTokenSource.Token);

        _mockDecryptorBase.Verify(x => x.ExecuteDecryptionProcessAsync(
            It.Is<FileTransferInstruction>(t => t.SourcePath == sourcePath && t.DestinationPath == destinationPath),
            It.IsAny<ReadOnlyMemory<byte>>(),
            It.IsAny<ILogger>(),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task DecryptFileAsync_WithPlatformSpecificPaths_HandlesCorrectly()
    {
        var testId = Guid.NewGuid().ToString("N")[..8];
        string sourcePath, destinationPath;

        if (OperatingSystem.IsWindows())
        {
            sourcePath = Path.Combine(_tempDirectory, $"windows_encrypted_{testId}.enc");
            destinationPath = Path.Combine(_tempDirectory, $"windows_decrypted_{testId}.txt");
        }
        else if (OperatingSystem.IsLinux())
        {
            sourcePath = Path.Combine(_tempDirectory, $"linux_encrypted_{testId}.enc");
            destinationPath = Path.Combine(_tempDirectory, $"linux_decrypted_{testId}.txt");
        }
        else if (OperatingSystem.IsMacOS())
        {
            sourcePath = Path.Combine(_tempDirectory, $"macos_encrypted_{testId}.enc");
            destinationPath = Path.Combine(_tempDirectory, $"macos_decrypted_{testId}.txt");
        }
        else
        {
            sourcePath = Path.Combine(_tempDirectory, $"other_encrypted_{testId}.enc");
            destinationPath = Path.Combine(_tempDirectory, $"other_decrypted_{testId}.txt");
        }

        var transferInstruction = new FileTransferInstruction(sourcePath, destinationPath);

        var decryptionKey = new byte[32];
        RandomNumberGenerator.Fill(decryptionKey);
        var input = new ChaCha20Poly1305DecryptionInput(decryptionKey);

        _mockDecryptorBase
            .Setup(x => x.ExecuteDecryptionProcessAsync(
                It.IsAny<FileTransferInstruction>(),
                It.IsAny<ReadOnlyMemory<byte>>(),
                It.IsAny<ILogger>(),
                It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        await _decryptionService.DecryptFileAsync(transferInstruction, input, _cancellationTokenSource.Token);

        _mockDecryptorBase.Verify(x => x.ExecuteDecryptionProcessAsync(
            It.Is<FileTransferInstruction>(t => t.SourcePath == sourcePath && t.DestinationPath == destinationPath),
            It.IsAny<ReadOnlyMemory<byte>>(),
            It.IsAny<ILogger>(),
            It.IsAny<CancellationToken>()), Times.Once);

        Assert.Contains(Path.DirectorySeparatorChar.ToString(), sourcePath);
        Assert.Contains(Path.DirectorySeparatorChar.ToString(), destinationPath);
    }

    [Fact]
    public async Task DecryptFileAsync_WithMultipleDecryptions_HandlesEachIndependently()
    {
        var (sourcePath1, destinationPath1) =
            CreateTestPaths($"{nameof(DecryptFileAsync_WithMultipleDecryptions_HandlesEachIndependently)}_First");
        var (sourcePath2, destinationPath2) =
            CreateTestPaths($"{nameof(DecryptFileAsync_WithMultipleDecryptions_HandlesEachIndependently)}_Second");

        var transferInstruction1 = new FileTransferInstruction(sourcePath1, destinationPath1);
        var transferInstruction2 = new FileTransferInstruction(sourcePath2, destinationPath2);

        var decryptionKey1 = new byte[32];
        var decryptionKey2 = new byte[32];
        RandomNumberGenerator.Fill(decryptionKey1);
        RandomNumberGenerator.Fill(decryptionKey2);

        var input1 = new ChaCha20Poly1305DecryptionInput(decryptionKey1);
        var input2 = new ChaCha20Poly1305DecryptionInput(decryptionKey2);

        var capturedPasswords = new List<ReadOnlyMemory<byte>>();
        var capturedInstructions = new List<FileTransferInstruction>();

        _mockDecryptorBase
            .Setup(x => x.ExecuteDecryptionProcessAsync(
                It.IsAny<FileTransferInstruction>(),
                It.IsAny<ReadOnlyMemory<byte>>(),
                It.IsAny<ILogger>(),
                It.IsAny<CancellationToken>()))
            .Callback<FileTransferInstruction, ReadOnlyMemory<byte>, ILogger, CancellationToken>((instruction, password,
                _, _) =>
            {
                capturedInstructions.Add(instruction);
                capturedPasswords.Add(password);
            })
            .Returns(Task.CompletedTask);

        await _decryptionService.DecryptFileAsync(transferInstruction1, input1, _cancellationTokenSource.Token);
        await _decryptionService.DecryptFileAsync(transferInstruction2, input2, _cancellationTokenSource.Token);

        Assert.Equal(2, capturedPasswords.Count);
        Assert.Equal(2, capturedInstructions.Count);

        Assert.True(capturedPasswords[0].Span.SequenceEqual(decryptionKey1),
            "First decryption should use the correct key");
        Assert.True(capturedPasswords[1].Span.SequenceEqual(decryptionKey2),
            "Second decryption should use the correct key");

        Assert.Equal(sourcePath1, capturedInstructions[0].SourcePath);
        Assert.Equal(destinationPath1, capturedInstructions[0].DestinationPath);
        Assert.Equal(sourcePath2, capturedInstructions[1].SourcePath);
        Assert.Equal(destinationPath2, capturedInstructions[1].DestinationPath);
    }

    [Fact]
    public async Task DecryptFileAsync_WithValidKey_Uses32ByteKey()
    {
        var (sourcePath, destinationPath) = CreateTestPaths(nameof(DecryptFileAsync_WithValidKey_Uses32ByteKey));
        var transferInstruction = new FileTransferInstruction(sourcePath, destinationPath);

        var decryptionKey = new byte[32];
        RandomNumberGenerator.Fill(decryptionKey);
        var input = new ChaCha20Poly1305DecryptionInput(decryptionKey);

        _mockDecryptorBase
            .Setup(x => x.ExecuteDecryptionProcessAsync(
                It.IsAny<FileTransferInstruction>(),
                It.IsAny<ReadOnlyMemory<byte>>(),
                It.IsAny<ILogger>(),
                It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        await _decryptionService.DecryptFileAsync(transferInstruction, input, _cancellationTokenSource.Token);

        _mockDecryptorBase.Verify(x => x.ExecuteDecryptionProcessAsync(
            It.IsAny<FileTransferInstruction>(),
            It.Is<ReadOnlyMemory<byte>>(password => password.Length == 32),
            It.IsAny<ILogger>(),
            It.IsAny<CancellationToken>()), Times.Once);
    }
}