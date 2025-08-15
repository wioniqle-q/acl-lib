using Acl.Fs.Cli.Abstractions.Services;
using Acl.Fs.Cli.Configuration;
using Acl.Fs.Cli.Models;
using Acl.Fs.Core.Abstractions.Service.Decryption.XChaCha20Poly1305;
using Acl.Fs.Core.Abstractions.Service.Encryption.XChaCha20Poly1305;
using Acl.Fs.Core.Models;
using Acl.Fs.Core.Models.XChaCha20Poly1305;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Acl.Fs.Cli.Services;

internal sealed class CryptoService(
    IEncryptionService encryptionService,
    IDecryptionService decryptionService,
    IOptions<CryptoSettings> settings,
    ILogger<CryptoService> logger,
    FileOperationValidator validator,
    IGlobalCancellationManager globalCancellationManager,
    IOperationResultHandler operationResultHandler) : ICryptoService
{
    private readonly IDecryptionService _decryptionService =
        decryptionService ?? throw new ArgumentNullException(nameof(decryptionService));

    private readonly IEncryptionService _encryptionService =
        encryptionService ?? throw new ArgumentNullException(nameof(encryptionService));

    private readonly IGlobalCancellationManager _globalCancellationManager =
        globalCancellationManager ?? throw new ArgumentNullException(nameof(globalCancellationManager));

    private readonly ILogger<CryptoService> _logger = logger ?? throw new ArgumentNullException(nameof(logger));

    private readonly IOperationResultHandler _operationResultHandler =
        operationResultHandler ?? throw new ArgumentNullException(nameof(operationResultHandler));

    private readonly SemaphoreSlim _semaphore = new(settings.Value.MaxConcurrency, settings.Value.MaxConcurrency);
    private readonly CryptoSettings _settings = settings.Value ?? throw new ArgumentNullException(nameof(settings));

    private readonly FileOperationValidator
        _validator = validator ?? throw new ArgumentNullException(nameof(validator));

    public void Dispose()
    {
        _semaphore.Dispose();
    }

    public async Task EncryptFolderAsync(string sourceFolder, string destinationFolder, ReadOnlyMemory<byte> password,
        CancellationToken cancellationToken = default)
    {
        if (Directory.Exists(sourceFolder) is not true)
            throw new DirectoryNotFoundException($"Source folder not found: {sourceFolder}");
        if (Directory.GetFiles(sourceFolder, "*", SearchOption.AllDirectories).Length is 0)
            throw new FileNotFoundException($"No files found in: {sourceFolder}");

        Directory.CreateDirectory(destinationFolder);

        var files = Directory.GetFiles(sourceFolder, "*", SearchOption.AllDirectories);
        _logger.LogInformation("Starting encryption of {FileCount} files from {SourceFolder} to {DestinationFolder}",
            files.Length, sourceFolder, destinationFolder);

        var combinedToken = _globalCancellationManager.CombineWith(cancellationToken);
        var tasks = files.Select(file =>
            EncryptFileWithSemaphoreAsync(file, sourceFolder, destinationFolder, password, combinedToken));
        await Task.WhenAll(tasks);

        _logger.LogInformation("Encryption completed successfully");
    }

    public async Task DecryptFolderAsync(string encryptedFolder, string decryptedFolder, ReadOnlyMemory<byte> password,
        CancellationToken cancellationToken = default)
    {
        if (Directory.Exists(encryptedFolder) is not true)
            throw new DirectoryNotFoundException($"Encrypted folder not found: {encryptedFolder}");

        var files = Directory.GetFiles(encryptedFolder, $"{_settings.DefaultEncryptedPrefix}*",
            SearchOption.AllDirectories);
        if (files.Length is 0)
            throw new FileNotFoundException($"No encrypted files found in: {encryptedFolder}");

        Directory.CreateDirectory(decryptedFolder);

        var combinedToken = _globalCancellationManager.CombineWith(cancellationToken);

        var request = new OperationRequest
        {
            Files = files,
            ProcessFileAsync = async (file, token) =>
            {
                await DecryptFileWithSemaphoreAsync(file, encryptedFolder, decryptedFolder, password, token, false);
            },
            CancellationToken = combinedToken,
            OperationName = "Decryption",
            CleanupPath = decryptedFolder,
            MaxConsecutiveFailures = 4,
            MaxFailureRatio = 0.8,
            MinFilesBeforeRatioCheck = 2
        };

        await _operationResultHandler.HandleOperationAsync(request);
    }

    private async Task EncryptFileWithSemaphoreAsync(string filePath, string sourceFolder, string destinationFolder,
        ReadOnlyMemory<byte> password, CancellationToken cancellationToken)
    {
        await _semaphore.WaitAsync(cancellationToken);
        try
        {
            await _globalCancellationManager.ExecuteWithCancellationOnCryptoErrorAsync(
                token => EncryptFileAsync(filePath, sourceFolder, destinationFolder, password, token),
                cancellationToken);
        }
        finally
        {
            _semaphore.Release();
        }
    }

    private async Task DecryptFileWithSemaphoreAsync(string filePath, string encryptedFolder, string decryptedFolder,
        ReadOnlyMemory<byte> password, CancellationToken cancellationToken, bool useGlobalCancellation = true)
    {
        await _semaphore.WaitAsync(cancellationToken);
        try
        {
            if (useGlobalCancellation)
                await _globalCancellationManager.ExecuteWithCancellationOnCryptoErrorAsync(
                    token => DecryptFileAsync(filePath, encryptedFolder, decryptedFolder, password, token),
                    cancellationToken);
            else
                await DecryptFileAsync(filePath, encryptedFolder, decryptedFolder, password, cancellationToken);
        }
        finally
        {
            _semaphore.Release();
        }
    }

    private async Task EncryptFileAsync(string filePath, string sourceFolder, string destinationFolder,
        ReadOnlyMemory<byte> password, CancellationToken cancellationToken)
    {
        var relativePath = Path.GetRelativePath(sourceFolder, filePath);
        var fileName = Path.GetFileName(relativePath);
        var directory = Path.GetDirectoryName(relativePath) ?? string.Empty;

        var encryptedFileName = $"{_settings.DefaultEncryptedPrefix}{fileName}";
        var destinationPath = Path.Combine(destinationFolder, directory, encryptedFileName);

        _validator.ValidateFileOperation(filePath, destinationPath, _settings, true);

        Directory.CreateDirectory(Path.GetDirectoryName(destinationPath)!);

        var transferInstruction = new FileTransferInstruction(filePath, destinationPath);

        _logger.LogDebug("Encrypting file: {SourceFile} -> {DestinationFile}", filePath, destinationPath);

        try
        {
            using var encryptionInput = new XChaCha20Poly1305EncryptionInput(password);
            await _encryptionService.EncryptFileAsync(transferInstruction, encryptionInput, cancellationToken);
        }
        catch (Exception ex)
        {
            _validator.CleanupFailedOperation(destinationPath, destinationFolder);
            _logger.LogError(ex, "Failed to encrypt file: {SourceFile} -> {DestinationFile}", filePath,
                destinationPath);
            throw;
        }
    }

    private async Task DecryptFileAsync(string filePath, string encryptedFolder, string decryptedFolder,
        ReadOnlyMemory<byte> password, CancellationToken cancellationToken)
    {
        var relativePath = Path.GetRelativePath(encryptedFolder, filePath);
        var fileName = Path.GetFileName(relativePath);
        var directory = Path.GetDirectoryName(relativePath) ?? string.Empty;

        if (fileName.StartsWith(_settings.DefaultEncryptedPrefix) is not true)
        {
            _logger.LogWarning("File {FileName} does not have the expected encrypted prefix {Prefix}", fileName,
                _settings.DefaultEncryptedPrefix);
            return;
        }

        var decryptedFileName = fileName[_settings.DefaultEncryptedPrefix.Length..];
        var destinationPath = Path.Combine(decryptedFolder, directory, decryptedFileName);

        _validator.ValidateFileOperation(filePath, destinationPath, _settings);

        Directory.CreateDirectory(Path.GetDirectoryName(destinationPath)!);

        var transferInstruction = new FileTransferInstruction(filePath, destinationPath);

        _logger.LogDebug("Decrypting file: {SourceFile} -> {DestinationFile}", filePath, destinationPath);

        try
        {
            using var decryptionInput = new XChaCha20Poly1305DecryptionInput(password);
            await _decryptionService.DecryptFileAsync(transferInstruction, decryptionInput, cancellationToken);
        }
        catch (Exception ex)
        {
            _validator.CleanupFailedOperation(destinationPath, decryptedFolder);
            _logger.LogError(ex, "Failed to decrypt file: {SourceFile} -> {DestinationFile}", filePath,
                destinationPath);
            throw;
        }
    }
}