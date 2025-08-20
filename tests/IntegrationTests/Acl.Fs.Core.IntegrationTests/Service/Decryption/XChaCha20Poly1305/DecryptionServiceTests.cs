using System.Security.Cryptography;
using Acl.Fs.Audit.Extensions;
using Acl.Fs.Core.Abstractions.Service.Decryption.XChaCha20Poly1305;
using Acl.Fs.Core.Abstractions.Service.Encryption.XChaCha20Poly1305;
using Acl.Fs.Core.Extensions;
using Acl.Fs.Core.Extensions.Decryption;
using Acl.Fs.Core.Extensions.Encryption;
using Acl.Fs.Core.Models;
using Acl.Fs.Core.Models.XChaCha20Poly1305;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Acl.Fs.Core.IntegrationTests.Service.Decryption.XChaCha20Poly1305;

public sealed class DecryptionServiceTests : IDisposable
{
    private readonly IDecryptionService _decryptionService;
    private readonly IEncryptionService _encryptionService;
    private readonly ServiceProvider _serviceProvider;
    private readonly string _testDataDirectory;
    private readonly string _testDecryptedDirectory;
    private readonly string _testOutputDirectory;

    private bool _disposed;

    public DecryptionServiceTests()
    {
        _testDataDirectory = Path.Combine(Path.GetTempPath(), "AclFsTests", "TestData", Guid.NewGuid().ToString());
        _testOutputDirectory = Path.Combine(Path.GetTempPath(), "AclFsTests", "Output", Guid.NewGuid().ToString());
        _testDecryptedDirectory =
            Path.Combine(Path.GetTempPath(), "AclFsTests", "Decrypted", Guid.NewGuid().ToString());

        Directory.CreateDirectory(_testDataDirectory);
        Directory.CreateDirectory(_testOutputDirectory);
        Directory.CreateDirectory(_testDecryptedDirectory);

        var services = new ServiceCollection();
        services.AddLogging(builder => builder.AddConsole().SetMinimumLevel(LogLevel.Warning));
        services.AddAuditLogger();
        services.AddAclFsCore();
        services.AddXChaCha20Poly1305Factory();

        services.AddEncryptionComponents();
        services.AddXChaCha20Poly1305EncryptionServices();
        services.AddDecryptionComponents();
        services.AddXChaCha20Poly1305DecryptionServices();

        _serviceProvider = services.BuildServiceProvider();
        _encryptionService = _serviceProvider.GetRequiredService<IEncryptionService>();
        _decryptionService = _serviceProvider.GetRequiredService<IDecryptionService>();
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    [Fact]
    public async Task DecryptFileAsync_WithValidEncryptedFile_ShouldDecryptSuccessfully()
    {
        const string originalContent =
            "This is a test file content for encryption and decryption testing with XChaCha20Poly1305.";
        var sourcePath = Path.Combine(_testDataDirectory, "original-file.txt");
        var encryptedPath = Path.Combine(_testOutputDirectory, "encrypted-file.enc");
        var decryptedPath = Path.Combine(_testDecryptedDirectory, "decrypted-file.txt");

        await File.WriteAllTextAsync(sourcePath, originalContent);

        var key = new byte[32];
        RandomNumberGenerator.Fill(key);

        var encryptInstruction = new FileTransferInstruction(sourcePath, encryptedPath);
        var encryptionInput = new XChaCha20Poly1305EncryptionInput(key);

        using var cancellationTokenSource = new CancellationTokenSource(TimeSpan.FromMinutes(2));

        await _encryptionService.EncryptFileAsync(encryptInstruction, encryptionInput, cancellationTokenSource.Token);

        var decryptInstruction = new FileTransferInstruction(encryptedPath, decryptedPath);
        var decryptionInput = new XChaCha20Poly1305DecryptionInput(key);

        await _decryptionService.DecryptFileAsync(decryptInstruction, decryptionInput, cancellationTokenSource.Token);

        Assert.True(File.Exists(decryptedPath), "Decrypted file should exist");

        var decryptedContent = await File.ReadAllTextAsync(decryptedPath, cancellationTokenSource.Token);
        Assert.Equal(originalContent, decryptedContent);
    }

    [Fact]
    public async Task DecryptFileAsync_WithLargeFile_ShouldDecryptSuccessfully()
    {
        var sourcePath = Path.Combine(_testDataDirectory, "large-original-file.bin");
        var encryptedPath = Path.Combine(_testOutputDirectory, "large-encrypted-file.enc");
        var decryptedPath = Path.Combine(_testDecryptedDirectory, "large-decrypted-file.bin");

        var originalContent = new byte[5 * 1024 * 1024];
        RandomNumberGenerator.Fill(originalContent);
        await File.WriteAllBytesAsync(sourcePath, originalContent);

        var key = new byte[32];
        RandomNumberGenerator.Fill(key);

        var encryptInstruction = new FileTransferInstruction(sourcePath, encryptedPath);
        var encryptionInput = new XChaCha20Poly1305EncryptionInput(key);

        using var cancellationTokenSource = new CancellationTokenSource(TimeSpan.FromMinutes(3));

        await _encryptionService.EncryptFileAsync(encryptInstruction, encryptionInput, cancellationTokenSource.Token);

        var decryptInstruction = new FileTransferInstruction(encryptedPath, decryptedPath);
        var decryptionInput = new XChaCha20Poly1305DecryptionInput(key);

        await _decryptionService.DecryptFileAsync(decryptInstruction, decryptionInput, cancellationTokenSource.Token);

        Assert.True(File.Exists(decryptedPath), "Decrypted large file should exist");

        var decryptedContent = await File.ReadAllBytesAsync(decryptedPath, cancellationTokenSource.Token);
        Assert.Equal(originalContent, decryptedContent);
    }

    [Fact]
    public async Task DecryptFileAsync_WithEmptyFile_ShouldDecryptSuccessfully()
    {
        var sourcePath = Path.Combine(_testDataDirectory, "empty-original-file.txt");
        var encryptedPath = Path.Combine(_testOutputDirectory, "empty-encrypted-file.enc");
        var decryptedPath = Path.Combine(_testDecryptedDirectory, "empty-decrypted-file.txt");

        await File.WriteAllTextAsync(sourcePath, string.Empty);

        var key = new byte[32];
        RandomNumberGenerator.Fill(key);

        var encryptInstruction = new FileTransferInstruction(sourcePath, encryptedPath);
        var encryptionInput = new XChaCha20Poly1305EncryptionInput(key);

        using var cancellationTokenSource = new CancellationTokenSource(TimeSpan.FromMinutes(1));

        await _encryptionService.EncryptFileAsync(encryptInstruction, encryptionInput, cancellationTokenSource.Token);

        var decryptInstruction = new FileTransferInstruction(encryptedPath, decryptedPath);
        var decryptionInput = new XChaCha20Poly1305DecryptionInput(key);

        await _decryptionService.DecryptFileAsync(decryptInstruction, decryptionInput, cancellationTokenSource.Token);

        Assert.True(File.Exists(decryptedPath), "Decrypted empty file should exist");

        var decryptedContent = await File.ReadAllTextAsync(decryptedPath, cancellationTokenSource.Token);
        Assert.Equal(string.Empty, decryptedContent);
    }

    [Fact]
    public async Task DecryptFileAsync_WithWrongKey_ShouldThrowException()
    {
        const string originalContent = "This content will be encrypted with one key but decrypted with another.";
        var sourcePath = Path.Combine(_testDataDirectory, "wrong-key-original-file.txt");
        var encryptedPath = Path.Combine(_testOutputDirectory, "wrong-key-encrypted-file.enc");
        var decryptedPath = Path.Combine(_testDecryptedDirectory, "wrong-key-decrypted-file.txt");

        await File.WriteAllTextAsync(sourcePath, originalContent);

        var encryptionKey = new byte[32];
        var decryptionKey = new byte[32];
        RandomNumberGenerator.Fill(encryptionKey);
        RandomNumberGenerator.Fill(decryptionKey);

        var encryptInstruction = new FileTransferInstruction(sourcePath, encryptedPath);
        var encryptionInput = new XChaCha20Poly1305EncryptionInput(encryptionKey);

        using var cancellationTokenSource = new CancellationTokenSource(TimeSpan.FromMinutes(1));

        await _encryptionService.EncryptFileAsync(encryptInstruction, encryptionInput, cancellationTokenSource.Token);

        var decryptInstruction = new FileTransferInstruction(encryptedPath, decryptedPath);
        var decryptionInput = new XChaCha20Poly1305DecryptionInput(decryptionKey);

        await Assert.ThrowsAnyAsync<Exception>(async () =>
            await _decryptionService.DecryptFileAsync(decryptInstruction, decryptionInput,
                cancellationTokenSource.Token));
    }

    [Fact]
    public async Task DecryptFileAsync_WithInvalidEncryptedFile_ShouldThrowException()
    {
        var invalidEncryptedPath = Path.Combine(_testDataDirectory, "invalid-encrypted-file.enc");
        var decryptedPath = Path.Combine(_testDecryptedDirectory, "invalid-decrypted-file.txt");

        await File.WriteAllTextAsync(invalidEncryptedPath, "This is not a valid encrypted file");

        var key = new byte[32];
        RandomNumberGenerator.Fill(key);

        var decryptInstruction = new FileTransferInstruction(invalidEncryptedPath, decryptedPath);
        var decryptionInput = new XChaCha20Poly1305DecryptionInput(key);

        using var cancellationTokenSource = new CancellationTokenSource(TimeSpan.FromMinutes(1));

        await Assert.ThrowsAnyAsync<Exception>(async () =>
            await _decryptionService.DecryptFileAsync(decryptInstruction, decryptionInput,
                cancellationTokenSource.Token));
    }

    [Fact]
    public async Task DecryptFileAsync_WithNonExistentFile_ShouldThrowException()
    {
        var nonExistentPath = Path.Combine(_testDataDirectory, "non-existent-file.enc");
        var decryptedPath = Path.Combine(_testDecryptedDirectory, "non-existent-decrypted-file.txt");

        var key = new byte[32];
        RandomNumberGenerator.Fill(key);

        var decryptInstruction = new FileTransferInstruction(nonExistentPath, decryptedPath);
        var decryptionInput = new XChaCha20Poly1305DecryptionInput(key);

        using var cancellationTokenSource = new CancellationTokenSource(TimeSpan.FromMinutes(1));

        var exception = await Assert.ThrowsAnyAsync<Exception>(async () =>
            await _decryptionService.DecryptFileAsync(decryptInstruction, decryptionInput,
                cancellationTokenSource.Token));

        Assert.True(exception is FileNotFoundException or DirectoryNotFoundException or UnauthorizedAccessException);
    }

    [Fact]
    public async Task DecryptFileAsync_MultipleSequentialOperations_ShouldWorkCorrectly()
    {
        var testCases = new List<(string source, string encrypted, string decrypted, string content)>();

        for (var i = 0; i < 3; i++)
        {
            var sourcePath = Path.Combine(_testDataDirectory, $"sequential-original-{i}.txt");
            var encryptedPath = Path.Combine(_testOutputDirectory, $"sequential-encrypted-{i}.enc");
            var decryptedPath = Path.Combine(_testDecryptedDirectory, $"sequential-decrypted-{i}.txt");
            var content =
                $"Sequential test content {i} - this content should be preserved through encryption and decryption.";

            await File.WriteAllTextAsync(sourcePath, content);
            testCases.Add((sourcePath, encryptedPath, decryptedPath, content));
        }

        var key = new byte[32];
        RandomNumberGenerator.Fill(key);

        using var cancellationTokenSource = new CancellationTokenSource(TimeSpan.FromMinutes(3));

        foreach (var (source, encrypted, _, _) in testCases)
        {
            var encryptInstruction = new FileTransferInstruction(source, encrypted);
            var encryptionInput = new XChaCha20Poly1305EncryptionInput(key);
            await _encryptionService.EncryptFileAsync(encryptInstruction, encryptionInput,
                cancellationTokenSource.Token);
        }

        foreach (var (_, encrypted, decrypted, _) in testCases)
        {
            var decryptInstruction = new FileTransferInstruction(encrypted, decrypted);
            var decryptionInput = new XChaCha20Poly1305DecryptionInput(key);
            await _decryptionService.DecryptFileAsync(decryptInstruction, decryptionInput,
                cancellationTokenSource.Token);
        }

        foreach (var (_, _, decrypted, originalContent) in testCases)
        {
            Assert.True(File.Exists(decrypted), $"Decrypted file should exist: {decrypted}");
            var decryptedContent = await File.ReadAllTextAsync(decrypted, cancellationTokenSource.Token);
            Assert.Equal(originalContent, decryptedContent);
        }
    }

    [Fact]
    public async Task DecryptFileAsync_WithBinaryFile_ShouldDecryptSuccessfully()
    {
        var sourcePath = Path.Combine(_testDataDirectory, "binary-original-file.bin");
        var encryptedPath = Path.Combine(_testOutputDirectory, "binary-encrypted-file.enc");
        var decryptedPath = Path.Combine(_testDecryptedDirectory, "binary-decrypted-file.bin");

        var binaryContent = new byte[1024];
        for (var i = 0; i < binaryContent.Length; i++) binaryContent[i] = (byte)(i % 256);

        await File.WriteAllBytesAsync(sourcePath, binaryContent);

        var key = new byte[32];
        RandomNumberGenerator.Fill(key);

        var encryptInstruction = new FileTransferInstruction(sourcePath, encryptedPath);
        var encryptionInput = new XChaCha20Poly1305EncryptionInput(key);

        using var cancellationTokenSource = new CancellationTokenSource(TimeSpan.FromMinutes(1));

        await _encryptionService.EncryptFileAsync(encryptInstruction, encryptionInput, cancellationTokenSource.Token);

        var decryptInstruction = new FileTransferInstruction(encryptedPath, decryptedPath);
        var decryptionInput = new XChaCha20Poly1305DecryptionInput(key);

        await _decryptionService.DecryptFileAsync(decryptInstruction, decryptionInput, cancellationTokenSource.Token);

        Assert.True(File.Exists(decryptedPath), "Decrypted binary file should exist");

        var decryptedContent = await File.ReadAllBytesAsync(decryptedPath, cancellationTokenSource.Token);
        Assert.Equal(binaryContent, decryptedContent);
    }

    [Fact]
    public async Task DecryptFileAsync_RoundTripTest_ShouldPreserveDataIntegrity()
    {
        var originalPath = Path.Combine(_testDataDirectory, "roundtrip-original.txt");
        var encryptedPath = Path.Combine(_testOutputDirectory, "roundtrip-encrypted.enc");
        var decryptedPath = Path.Combine(_testDecryptedDirectory, "roundtrip-decrypted.txt");

        const string originalContent =
            "!@#$%^&*()_+-=[]{}|;':\",./<>?`~àáâãäåæçèéêëìíîïðñòóôõöøùúûüýþÿ";
        await File.WriteAllTextAsync(originalPath, originalContent);

        var key = new byte[32];
        RandomNumberGenerator.Fill(key);

        using var cancellationTokenSource = new CancellationTokenSource(TimeSpan.FromMinutes(1));

        var encryptInstruction = new FileTransferInstruction(originalPath, encryptedPath);
        var encryptionInput = new XChaCha20Poly1305EncryptionInput(key);
        await _encryptionService.EncryptFileAsync(encryptInstruction, encryptionInput, cancellationTokenSource.Token);

        var decryptInstruction = new FileTransferInstruction(encryptedPath, decryptedPath);
        var decryptionInput = new XChaCha20Poly1305DecryptionInput(key);
        await _decryptionService.DecryptFileAsync(decryptInstruction, decryptionInput, cancellationTokenSource.Token);

        var decryptedContent = await File.ReadAllTextAsync(decryptedPath, cancellationTokenSource.Token);
        Assert.Equal(originalContent, decryptedContent);

        var originalSize = new FileInfo(originalPath).Length;
        var decryptedSize = new FileInfo(decryptedPath).Length;
        Assert.Equal(originalSize, decryptedSize);
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

                if (Directory.Exists(_testDecryptedDirectory)) Directory.Delete(_testDecryptedDirectory, true);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error during cleanup: {ex.Message}");
            }
        }

        _disposed = true;
    }

    ~DecryptionServiceTests()
    {
        Dispose(false);
    }
}