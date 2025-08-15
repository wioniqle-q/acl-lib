using System.Security.Cryptography;
using System.Text;
using Acl.Fs.Cli.Abstractions.Services;
using Microsoft.Extensions.Logging;

namespace Acl.Fs.Cli.Services;

internal sealed class OperationExecutor(
    ICryptoService cryptoService,
    ILogger<OperationExecutor> logger,
    ILoggingService loggingService)
    : IOperationExecutor
{
    private readonly ICryptoService _cryptoService =
        cryptoService ?? throw new ArgumentNullException(nameof(cryptoService));

    private readonly ILogger<OperationExecutor> _logger = logger ?? throw new ArgumentNullException(nameof(logger));

    private readonly ILoggingService _loggingService =
        loggingService ?? throw new ArgumentNullException(nameof(loggingService));

    public async Task<bool> ExecuteEncryptionAsync(string sourceFolder, string destinationFolder, string password)
    {
        var operationId = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss");
        var operationLogger = _loggingService.CreateOperationLogger("encryption", operationId);

        var passwordBytes = Encoding.UTF8.GetBytes(password);
        var passwordMemory = new ReadOnlyMemory<byte>(passwordBytes);

        try
        {
            _logger.LogInformation("Starting encryption operation {OperationId} at {Timestamp} UTC", operationId,
                DateTime.UtcNow);

            operationLogger.Information("=== ENCRYPTION OPERATION START ===");
            operationLogger.Information("Operation ID: {OperationId}", operationId);
            operationLogger.Information("Start Time: {Timestamp} UTC", DateTime.UtcNow);
            operationLogger.Information("Source folder: {SourceFolder}", sourceFolder);
            operationLogger.Information("Destination folder: {DestinationFolder}", destinationFolder);

            _logger.LogInformation("Source folder: {SourceFolder}", sourceFolder);
            _logger.LogInformation("Destination folder: {DestinationFolder}", destinationFolder);

            using var cts = new CancellationTokenSource();

            Console.CancelKeyPress += (_, e) =>
            {
                e.Cancel = true;
                cts.Cancel();
                _logger.LogWarning("Cancellation requested by user for operation {OperationId}", operationId);

                var cancelLogger = _loggingService.CreateOperationLogger("encryption", operationId + "-cancel");
                cancelLogger.Warning("Cancellation requested by user at {Timestamp} UTC", DateTime.UtcNow);
            };

            await _cryptoService.EncryptFolderAsync(sourceFolder, destinationFolder, passwordMemory, cts.Token);

            _logger.LogInformation("Encryption operation {OperationId} completed successfully at {Timestamp} UTC",
                operationId, DateTime.UtcNow);
            operationLogger.Information("Encryption completed successfully at {Timestamp} UTC", DateTime.UtcNow);
            operationLogger.Information("=== ENCRYPTION OPERATION END ===");
            return true;
        }
        catch (OperationCanceledException)
        {
            _logger.LogWarning("Encryption operation {OperationId} was cancelled at {Timestamp} UTC", operationId,
                DateTime.UtcNow);
            operationLogger.Warning("Encryption operation was cancelled at {Timestamp} UTC", DateTime.UtcNow);
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during encryption operation {OperationId} at {Timestamp} UTC", operationId,
                DateTime.UtcNow);
            operationLogger.Error(ex, "Error during encryption at {Timestamp} UTC", DateTime.UtcNow);

            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }

    public async Task<bool> ExecuteDecryptionAsync(string encryptedFolder, string decryptedFolder, string password)
    {
        var operationId = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss");
        var operationLogger = _loggingService.CreateOperationLogger("decryption", operationId);

        var passwordBytes = Encoding.UTF8.GetBytes(password);
        var passwordMemory = new ReadOnlyMemory<byte>(passwordBytes);

        try
        {
            _logger.LogInformation("Starting decryption operation {OperationId} at {Timestamp} UTC", operationId,
                DateTime.UtcNow);

            operationLogger.Information("=== DECRYPTION OPERATION START ===");
            operationLogger.Information("Operation ID: {OperationId}", operationId);
            operationLogger.Information("Start Time: {Timestamp} UTC", DateTime.UtcNow);
            operationLogger.Information("Encrypted folder: {EncryptedFolder}", encryptedFolder);
            operationLogger.Information("Decrypted folder: {DecryptedFolder}", decryptedFolder);

            _logger.LogInformation("Encrypted folder: {EncryptedFolder}", encryptedFolder);
            _logger.LogInformation("Decrypted folder: {DecryptedFolder}", decryptedFolder);

            using var cts = new CancellationTokenSource();

            Console.CancelKeyPress += (_, e) =>
            {
                e.Cancel = true;
                cts.Cancel();
                _logger.LogWarning("Cancellation requested by user for operation {OperationId}", operationId);

                var cancelLogger = _loggingService.CreateOperationLogger("decryption", operationId + "-cancel");
                cancelLogger.Warning("Cancellation requested by user at {Timestamp} UTC", DateTime.UtcNow);
            };

            await _cryptoService.DecryptFolderAsync(encryptedFolder, decryptedFolder, passwordMemory, cts.Token);

            _logger.LogInformation("Decryption operation {OperationId} completed successfully at {Timestamp} UTC",
                operationId, DateTime.UtcNow);
            operationLogger.Information("Decryption completed successfully at {Timestamp} UTC", DateTime.UtcNow);
            operationLogger.Information("=== DECRYPTION OPERATION END ===");
            return true;
        }
        catch (OperationCanceledException)
        {
            _logger.LogWarning("Decryption operation {OperationId} was cancelled at {Timestamp} UTC", operationId,
                DateTime.UtcNow);
            operationLogger.Warning("Decryption operation was cancelled at {Timestamp} UTC", DateTime.UtcNow);
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during decryption operation {OperationId} at {Timestamp} UTC", operationId,
                DateTime.UtcNow);
            operationLogger.Error(ex, "Error during decryption at {Timestamp} UTC", DateTime.UtcNow);

            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }
}