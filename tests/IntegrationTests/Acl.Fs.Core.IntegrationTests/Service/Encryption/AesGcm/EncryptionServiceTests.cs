using System.Security.Cryptography;
using Acl.Fs.Audit.Extensions;
using Acl.Fs.Core.Abstractions.Service.Encryption.AesGcm;
using Acl.Fs.Core.Extensions;
using Acl.Fs.Core.Extensions.Encryption;
using Acl.Fs.Core.Models;
using Acl.Fs.Core.Models.AesGcm;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Acl.Fs.Core.IntegrationTests.Service.Encryption.AesGcm;

public sealed class EncryptionServiceTests : IDisposable
{
    private readonly IEncryptionService _encryptionService;
    private readonly ServiceProvider _serviceProvider;
    private readonly string _testDataDirectory;
    private readonly string _testOutputDirectory;

    private bool _disposed;

    public EncryptionServiceTests()
    {
        _testDataDirectory = Path.Combine(Path.GetTempPath(), "AclFsTests", "TestData", Guid.NewGuid().ToString());
        _testOutputDirectory = Path.Combine(Path.GetTempPath(), "AclFsTests", "Output", Guid.NewGuid().ToString());
        Directory.CreateDirectory(_testDataDirectory);
        Directory.CreateDirectory(_testOutputDirectory);

        var services = new ServiceCollection();
        services.AddLogging(builder => builder.AddConsole().SetMinimumLevel(LogLevel.Warning));
        services.AddAuditLogger();
        services.AddAclFsCore();
        services.AddAesGcmFactory();
        services.AddEncryptionComponents();
        services.AddAesGcmEncryptionServices();

        _serviceProvider = services.BuildServiceProvider();
        _encryptionService = _serviceProvider.GetRequiredService<IEncryptionService>();
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    [Fact]
    public async Task EncryptFileAsync_WithValidInputs_ShouldEncryptFileSuccessfully()
    {
        const string sourceFileName = "test-file.txt";

        var sourcePath = Path.Combine(_testDataDirectory, sourceFileName);
        var destinationPath = Path.Combine(_testOutputDirectory, "encrypted-file.enc");

        const string testContent = "This is a test file content for encryption testing with AES-GCM.";
        await File.WriteAllTextAsync(sourcePath, testContent);

        var key = new byte[32];
        RandomNumberGenerator.Fill(key);

        var transferInstruction = new FileTransferInstruction(sourcePath, destinationPath);
        var encryptionInput = new AesEncryptionInput(key);

        using var cancellationTokenSource = new CancellationTokenSource(TimeSpan.FromMinutes(1));

        await _encryptionService.EncryptFileAsync(transferInstruction, encryptionInput, cancellationTokenSource.Token);

        Assert.True(File.Exists(destinationPath), "Encrypted file should exist");

        var encryptedFileInfo = new FileInfo(destinationPath);
        Assert.True(encryptedFileInfo.Length > 0, "Encrypted file should not be empty");

        var originalContent = await File.ReadAllBytesAsync(sourcePath, cancellationTokenSource.Token);
        var encryptedContent = await File.ReadAllBytesAsync(destinationPath, cancellationTokenSource.Token);

        Assert.NotEqual(originalContent, encryptedContent);
    }

    [Fact]
    public async Task EncryptFileAsync_WithAes128Key_ShouldEncryptFileSuccessfully()
    {
        var sourcePath = Path.Combine(_testDataDirectory, "aes128-test-file.txt");
        var destinationPath = Path.Combine(_testOutputDirectory, "aes128-encrypted-file.enc");

        const string testContent = "Testing AES-128 encryption with 16-byte key.";
        await File.WriteAllTextAsync(sourcePath, testContent);

        var key = new byte[16];
        RandomNumberGenerator.Fill(key);

        var transferInstruction = new FileTransferInstruction(sourcePath, destinationPath);
        var encryptionInput = new AesEncryptionInput(key);

        using var cancellationTokenSource = new CancellationTokenSource(TimeSpan.FromMinutes(1));

        await _encryptionService.EncryptFileAsync(transferInstruction, encryptionInput, cancellationTokenSource.Token);

        Assert.True(File.Exists(destinationPath), "Encrypted file with AES-128 should exist");

        var encryptedFileInfo = new FileInfo(destinationPath);
        Assert.True(encryptedFileInfo.Length > 0, "Encrypted file should not be empty");
    }

    [Fact]
    public async Task EncryptFileAsync_WithAes192Key_ShouldEncryptFileSuccessfully()
    {
        var sourcePath = Path.Combine(_testDataDirectory, "aes192-test-file.txt");
        var destinationPath = Path.Combine(_testOutputDirectory, "aes192-encrypted-file.enc");

        const string testContent = "Testing AES-192 encryption with 24-byte key.";
        await File.WriteAllTextAsync(sourcePath, testContent);

        var key = new byte[24];
        RandomNumberGenerator.Fill(key);

        var transferInstruction = new FileTransferInstruction(sourcePath, destinationPath);
        var encryptionInput = new AesEncryptionInput(key);

        using var cancellationTokenSource = new CancellationTokenSource(TimeSpan.FromMinutes(1));

        await _encryptionService.EncryptFileAsync(transferInstruction, encryptionInput, cancellationTokenSource.Token);

        Assert.True(File.Exists(destinationPath), "Encrypted file with AES-192 should exist");

        var encryptedFileInfo = new FileInfo(destinationPath);
        Assert.True(encryptedFileInfo.Length > 0, "Encrypted file should not be empty");
    }

    [Fact]
    public async Task EncryptFileAsync_WithAes256Key_ShouldEncryptFileSuccessfully()
    {
        var sourcePath = Path.Combine(_testDataDirectory, "aes256-test-file.txt");
        var destinationPath = Path.Combine(_testOutputDirectory, "aes256-encrypted-file.enc");

        const string testContent = "Testing AES-256 encryption with 32-byte key.";
        await File.WriteAllTextAsync(sourcePath, testContent);

        var key = new byte[32];
        RandomNumberGenerator.Fill(key);

        var transferInstruction = new FileTransferInstruction(sourcePath, destinationPath);
        var encryptionInput = new AesEncryptionInput(key);

        using var cancellationTokenSource = new CancellationTokenSource(TimeSpan.FromMinutes(1));

        await _encryptionService.EncryptFileAsync(transferInstruction, encryptionInput, cancellationTokenSource.Token);

        Assert.True(File.Exists(destinationPath), "Encrypted file with AES-256 should exist");

        var encryptedFileInfo = new FileInfo(destinationPath);
        Assert.True(encryptedFileInfo.Length > 0, "Encrypted file should not be empty");
    }

    [Fact]
    public async Task EncryptFileAsync_WithLargeFile_ShouldEncryptSuccessfully()
    {
        var sourcePath = Path.Combine(_testDataDirectory, "large-test-file.txt");
        var destinationPath = Path.Combine(_testOutputDirectory, "large-encrypted-file.enc");

        var largeContent = new byte[5 * 1024 * 1024];
        RandomNumberGenerator.Fill(largeContent);
        await File.WriteAllBytesAsync(sourcePath, largeContent);

        var key = new byte[32];
        RandomNumberGenerator.Fill(key);

        var transferInstruction = new FileTransferInstruction(sourcePath, destinationPath);
        var encryptionInput = new AesEncryptionInput(key);

        using var cancellationTokenSource = new CancellationTokenSource(TimeSpan.FromMinutes(2));

        await _encryptionService.EncryptFileAsync(transferInstruction, encryptionInput, cancellationTokenSource.Token);

        Assert.True(File.Exists(destinationPath), "Encrypted large file should exist");

        var encryptedFileInfo = new FileInfo(destinationPath);
        var originalFileInfo = new FileInfo(sourcePath);

        Assert.True(encryptedFileInfo.Length > originalFileInfo.Length,
            "Encrypted file should be larger due to metadata and authentication tags");
    }

    [Fact]
    public async Task EncryptFileAsync_WithEmptyFile_ShouldEncryptSuccessfully()
    {
        var sourcePath = Path.Combine(_testDataDirectory, "empty-file.txt");
        var destinationPath = Path.Combine(_testOutputDirectory, "empty-encrypted-file.enc");

        await File.WriteAllTextAsync(sourcePath, string.Empty);

        var key = new byte[32];
        RandomNumberGenerator.Fill(key);

        var transferInstruction = new FileTransferInstruction(sourcePath, destinationPath);
        var encryptionInput = new AesEncryptionInput(key);

        using var cancellationTokenSource = new CancellationTokenSource(TimeSpan.FromMinutes(1));

        await _encryptionService.EncryptFileAsync(transferInstruction, encryptionInput, cancellationTokenSource.Token);

        Assert.True(File.Exists(destinationPath), "Encrypted empty file should exist");

        var encryptedFileInfo = new FileInfo(destinationPath);
        Assert.True(encryptedFileInfo.Length > 0, "Encrypted empty file should contain metadata and headers");
    }

    [Fact]
    public async Task EncryptFileAsync_WithCancellationToken_ShouldRespectCancellation()
    {
        var sourcePath = Path.Combine(_testDataDirectory, "cancellation-test-file.txt");
        var destinationPath = Path.Combine(_testOutputDirectory, "cancellation-encrypted-file.enc");

        var content = new byte[1024 * 1024];
        RandomNumberGenerator.Fill(content);
        await File.WriteAllBytesAsync(sourcePath, content);

        var key = new byte[32];
        RandomNumberGenerator.Fill(key);

        var transferInstruction = new FileTransferInstruction(sourcePath, destinationPath);
        var encryptionInput = new AesEncryptionInput(key);

        using var cancellationTokenSource = new CancellationTokenSource(TimeSpan.FromMilliseconds(1));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await _encryptionService.EncryptFileAsync(transferInstruction, encryptionInput,
                cancellationTokenSource.Token));
    }

    [Fact]
    public async Task EncryptFileAsync_WithInvalidSourceFile_ShouldThrowException()
    {
        var sourcePath = Path.Combine(_testDataDirectory, "non-existent-file.txt");
        var destinationPath = Path.Combine(_testOutputDirectory, "output-file.enc");

        var key = new byte[32];
        RandomNumberGenerator.Fill(key);

        var transferInstruction = new FileTransferInstruction(sourcePath, destinationPath);
        var encryptionInput = new AesEncryptionInput(key);

        using var cancellationTokenSource = new CancellationTokenSource(TimeSpan.FromMinutes(1));

        var exception = await Assert.ThrowsAnyAsync<Exception>(async () =>
            await _encryptionService.EncryptFileAsync(transferInstruction, encryptionInput,
                cancellationTokenSource.Token));

        Assert.True(exception is FileNotFoundException or DirectoryNotFoundException or UnauthorizedAccessException);
    }

    [Fact]
    public async Task EncryptFileAsync_MultipleSequentialOperations_ShouldWorkCorrectly()
    {
        var files = new List<(string source, string destination)>();

        for (var i = 0; i < 3; i++)
        {
            var sourcePath = Path.Combine(_testDataDirectory, $"sequential-file-{i}.txt");
            var destinationPath = Path.Combine(_testOutputDirectory, $"sequential-encrypted-{i}.enc");

            await File.WriteAllTextAsync(sourcePath, $"Sequential test content {i}");
            files.Add((sourcePath, destinationPath));
        }

        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        var encryptionInput = new AesEncryptionInput(key);

        using var cancellationTokenSource = new CancellationTokenSource(TimeSpan.FromMinutes(2));

        foreach (var (source, destination) in files)
        {
            var transferInstruction = new FileTransferInstruction(source, destination);
            await _encryptionService.EncryptFileAsync(transferInstruction, encryptionInput,
                cancellationTokenSource.Token);
        }

        foreach (var (_, destination) in files)
        {
            Assert.True(File.Exists(destination), $"Encrypted file should exist: {destination}");
            Assert.True(new FileInfo(destination).Length > 0, $"Encrypted file should not be empty: {destination}");
        }
    }

    [Fact]
    public async Task EncryptFileAsync_WithBinaryFile_ShouldEncryptSuccessfully()
    {
        var sourcePath = Path.Combine(_testDataDirectory, "binary-test-file.bin");
        var destinationPath = Path.Combine(_testOutputDirectory, "binary-encrypted-file.enc");

        var binaryContent = new byte[1024];
        for (var i = 0; i < binaryContent.Length; i++) binaryContent[i] = (byte)(i % 256);

        await File.WriteAllBytesAsync(sourcePath, binaryContent);

        var key = new byte[32];
        RandomNumberGenerator.Fill(key);

        var transferInstruction = new FileTransferInstruction(sourcePath, destinationPath);
        var encryptionInput = new AesEncryptionInput(key);

        using var cancellationTokenSource = new CancellationTokenSource(TimeSpan.FromMinutes(1));

        await _encryptionService.EncryptFileAsync(transferInstruction, encryptionInput, cancellationTokenSource.Token);

        Assert.True(File.Exists(destinationPath), "Encrypted binary file should exist");

        var encryptedContent = await File.ReadAllBytesAsync(destinationPath, cancellationTokenSource.Token);
        Assert.NotEqual(binaryContent, encryptedContent);
        Assert.True(encryptedContent.Length > binaryContent.Length, "Encrypted file should be larger due to metadata");
    }

    [Fact]
    public async Task EncryptFileAsync_DifferentKeySizes_ShouldProduceDifferentResults()
    {
        var sourcePath = Path.Combine(_testDataDirectory, "keysize-test-file.txt");
        const string testContent = "Same content, different key sizes";
        await File.WriteAllTextAsync(sourcePath, testContent);

        var destinationPath128 = Path.Combine(_testOutputDirectory, "keysize-encrypted-128.enc");
        var destinationPath192 = Path.Combine(_testOutputDirectory, "keysize-encrypted-192.enc");
        var destinationPath256 = Path.Combine(_testOutputDirectory, "keysize-encrypted-256.enc");

        var key128 = new byte[16];
        RandomNumberGenerator.Fill(key128);
        var transferInstruction128 = new FileTransferInstruction(sourcePath, destinationPath128);
        var encryptionInput128 = new AesEncryptionInput(key128);

        var key192 = new byte[24];
        RandomNumberGenerator.Fill(key192);
        var transferInstruction192 = new FileTransferInstruction(sourcePath, destinationPath192);
        var encryptionInput192 = new AesEncryptionInput(key192);

        var key256 = new byte[32];
        RandomNumberGenerator.Fill(key256);
        var transferInstruction256 = new FileTransferInstruction(sourcePath, destinationPath256);
        var encryptionInput256 = new AesEncryptionInput(key256);

        using var cancellationTokenSource = new CancellationTokenSource(TimeSpan.FromMinutes(1));

        await _encryptionService.EncryptFileAsync(transferInstruction128, encryptionInput128,
            cancellationTokenSource.Token);
        await _encryptionService.EncryptFileAsync(transferInstruction192, encryptionInput192,
            cancellationTokenSource.Token);
        await _encryptionService.EncryptFileAsync(transferInstruction256, encryptionInput256,
            cancellationTokenSource.Token);

        Assert.True(File.Exists(destinationPath128), "AES-128 encrypted file should exist");
        Assert.True(File.Exists(destinationPath192), "AES-192 encrypted file should exist");
        Assert.True(File.Exists(destinationPath256), "AES-256 encrypted file should exist");

        var encrypted128 = await File.ReadAllBytesAsync(destinationPath128, cancellationTokenSource.Token);
        var encrypted192 = await File.ReadAllBytesAsync(destinationPath192, cancellationTokenSource.Token);
        var encrypted256 = await File.ReadAllBytesAsync(destinationPath256, cancellationTokenSource.Token);

        Assert.NotEqual(encrypted128, encrypted192);
        Assert.NotEqual(encrypted128, encrypted256);
        Assert.NotEqual(encrypted192, encrypted256);
    }

    private void Dispose(bool disposing)
    {
        if (_disposed) return;

        if (disposing)
        {
            _serviceProvider.Dispose();

            try
            {
                if (Directory.Exists(_testDataDirectory)) Directory.Delete(_testDataDirectory, true);

                if (Directory.Exists(_testOutputDirectory)) Directory.Delete(_testOutputDirectory, true);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error during cleanup: {ex.Message}");
            }
        }

        _disposed = true;
    }

    ~EncryptionServiceTests()
    {
        Dispose(false);
    }
}