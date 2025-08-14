using System.Collections.Concurrent;
using Acl.Fs.Cli.Abstractions.Services;
using Acl.Fs.Cli.Models;
using Acl.Fs.Cli.Exceptions;
using Microsoft.Extensions.Logging;

namespace Acl.Fs.Cli.Services;

internal sealed class OperationResultHandler(ILogger<OperationResultHandler> logger) : IOperationResultHandler
{
    private readonly ILogger<OperationResultHandler>
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

    public async Task<OperationResult> HandleOperationAsync(OperationRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        _logger.LogInformation("Starting {OperationName} for {FileCount} files",
            request.OperationName, request.Files.Length);

        var failedFiles = new ConcurrentBag<(string FilePath, Exception Exception)>();
        var fileAlreadyExistsCount = 0;
        var successCount = 0;
        var failureCount = 0;
        var consecutiveFailures = 0;
        var processedCount = 0;

        var earlyStopCts = new CancellationTokenSource();
        var earlyStopToken = CancellationTokenSource.CreateLinkedTokenSource(
            request.CancellationToken, earlyStopCts.Token).Token;

        var stopReason = string.Empty;
        bool wasStoppedEarly;

        try
        {
            var tasks = request.Files.Select(async file =>
            {
                try
                {
                    if (earlyStopToken.IsCancellationRequested)
                        return;

                    await request.ProcessFileAsync(file, earlyStopToken);

                    Interlocked.Increment(ref successCount);
                    Interlocked.Exchange(ref consecutiveFailures, 0);
                    Interlocked.Increment(ref processedCount);

                    _logger.LogDebug("Successfully processed: {FilePath}", file);
                }
                catch (Exception ex) when
                    ((ex is OperationCanceledException && earlyStopToken.IsCancellationRequested) is not true)
                {
                    var currentProcessedCount = Interlocked.Increment(ref processedCount);
                    
                    if (ex is FileAlreadyExistsException)
                    {
                        Interlocked.Increment(ref fileAlreadyExistsCount);
                        Interlocked.Exchange(ref consecutiveFailures, 0); 
                        failedFiles.Add((file, ex));
                        _logger.LogWarning("File already exists, skipping: {FilePath}", file);
                        return;
                    }
                    
                    var currentFailureCount = Interlocked.Increment(ref failureCount);
                    var currentConsecutiveFailures = Interlocked.Increment(ref consecutiveFailures);

                    failedFiles.Add((file, ex));
                    _logger.LogError(ex, "Failed to process file: {FilePath}", file);

                    var shouldStop = CheckEarlyStopConditions(
                        request, currentConsecutiveFailures, currentFailureCount,
                        currentProcessedCount, out var reason);

                    if (shouldStop && earlyStopCts.Token.IsCancellationRequested is not true)
                    {
                        stopReason = reason;
                        _logger.LogWarning(
                            "Early stopping {OperationName}: {Reason}. Processed: {ProcessedCount}, Failed: {FailedCount}, Success: {SuccessCount}, FileExists: {FileExistsCount}",
                            request.OperationName, reason, currentProcessedCount, currentFailureCount, successCount, fileAlreadyExistsCount);

                        await earlyStopCts.CancelAsync();
                    }
                }
            });

            await Task.WhenAll(tasks);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during {OperationName}", request.OperationName);
            throw;
        }
        finally
        {
            wasStoppedEarly = earlyStopCts.Token.IsCancellationRequested &&
                              request.CancellationToken.IsCancellationRequested is not true;
            earlyStopCts.Dispose();
        }

        var result = new OperationResult
        {
            SuccessCount = successCount,
            FailureCount = failureCount + fileAlreadyExistsCount, 
            ProcessedCount = processedCount,
            TotalCount = request.Files.Length,
            FailedFiles = failedFiles.ToList(),
            WasStoppedEarly = wasStoppedEarly,
            StopReason = stopReason
        };

        await HandleResultAsync(result, request, fileAlreadyExistsCount);
        return result;
    }

    private static bool CheckEarlyStopConditions(
        OperationRequest request,
        int consecutiveFailures,
        int totalFailures,
        int processedCount,
        out string stopReason)
    {
        stopReason = string.Empty;

        if (consecutiveFailures >= request.MaxConsecutiveFailures)
        {
            stopReason = $"Too many consecutive failures ({consecutiveFailures})";
            return true;
        }

        if (processedCount < request.MinFilesBeforeRatioCheck) return false;
        var failureRatio = (double)totalFailures / processedCount;

        if ((failureRatio >= request.MaxFailureRatio) is not true) return false;

        stopReason = $"High failure ratio ({failureRatio:P1})";
        return true;
    }

    private async Task HandleResultAsync(OperationResult result, OperationRequest request, int fileAlreadyExistsCount = 0)
    {
        var realFailures = result.FailureCount - fileAlreadyExistsCount;
        
        _logger.LogInformation(
            "{OperationName} completed. Success: {SuccessCount}/{TotalCount}, Real Failures: {RealFailures}, Files Already Exist: {FileExistsCount}, Processed: {ProcessedCount}",
            request.OperationName, result.SuccessCount, result.TotalCount, realFailures, fileAlreadyExistsCount, result.ProcessedCount);

        if (result.FailedFiles.Count > 0)
        {
            if (result.WasStoppedEarly && realFailures > 0)
            {
                await HandleEarlyStopCleanupAsync(request);

                throw new InvalidOperationException(
                    $"{request.OperationName} stopped early due to excessive failures. " +
                    $"This typically indicates an incorrect password or corrupted files. " +
                    $"Processed {result.ProcessedCount} files, {realFailures} failed, {result.SuccessCount} succeeded, {fileAlreadyExistsCount} files already existed.");
            }

            if (realFailures == 0)
            {
                _logger.LogInformation(
                    "{OperationName} completed successfully. All {FileExistsCount} failed files already existed at destination.",
                    request.OperationName, fileAlreadyExistsCount);
                return;
            }

            LogFailedFiles(result.FailedFiles);
            
            if (realFailures > 0 && realFailures == result.ProcessedCount - result.SuccessCount - fileAlreadyExistsCount)
                throw new InvalidOperationException(
                    $"All processed files with real errors failed. Check the password and file integrity. " +
                    $"Real failures: {realFailures}, Files already exist: {fileAlreadyExistsCount}");

            if (result.IsPartialSuccess || fileAlreadyExistsCount > 0)
                _logger.LogInformation(
                    "{OperationName} completed with partial success: {SuccessCount} files processed successfully, {RealFailures} files failed, {FileExistsCount} files already existed",
                    request.OperationName, result.SuccessCount, realFailures, fileAlreadyExistsCount);
        }
        else
        {
            _logger.LogInformation("{OperationName} completed successfully", request.OperationName);
        }
    }

    private async Task HandleEarlyStopCleanupAsync(OperationRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.CleanupPath))
            return;

        _logger.LogWarning(
            "Operation stopped early due to excessive failures. Cleaning up partially processed files...");

        try
        {
            if (Directory.Exists(request.CleanupPath))
            {
                var createdFiles = Directory.GetFiles(request.CleanupPath, "*", SearchOption.AllDirectories);

                var cleanupTasks = createdFiles.Select(async file =>
                {
                    try
                    {
                        await Task.Run(() => File.Delete(file));
                        _logger.LogDebug("Cleaned up file: {FilePath}", file);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed to cleanup file: {FilePath}", file);
                    }
                });

                await Task.WhenAll(cleanupTasks);

                try
                {
                    CleanupEmptyDirectories(request.CleanupPath, preserveRoot: true);
                    _logger.LogInformation("Cleaned up empty directories in: {CleanupPath}", request.CleanupPath);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to cleanup empty directories in: {CleanupPath}",
                        request.CleanupPath);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during cleanup process");
        }
    }

    private void CleanupEmptyDirectories(string path, bool preserveRoot = false)
    {
        try
        {
            if (!Directory.Exists(path))
            {
                _logger.LogDebug("Directory no longer exists, skipping cleanup: {Directory}", path);
                return;
            }

            foreach (var directory in Directory.GetDirectories(path))
            {
                CleanupEmptyDirectories(directory, preserveRoot: false);

                try
                {
                    if (Directory.Exists(directory) && Directory.GetFileSystemEntries(directory).Length == 0)
                    {
                        Directory.Delete(directory);
                        _logger.LogDebug("Removed empty directory: {Directory}", directory);
                    }
                }
                catch (DirectoryNotFoundException)
                {
                    _logger.LogDebug("Directory was already removed: {Directory}", directory);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to remove empty directory: {Directory}", directory);
                }
            }

            if (preserveRoot) return;

            try
            {
                if (Directory.Exists(path) && Directory.GetFileSystemEntries(path).Length == 0)
                {
                    Directory.Delete(path);
                    _logger.LogDebug("Removed empty directory: {Directory}", path);
                }
            }
            catch (DirectoryNotFoundException)
            {
                _logger.LogDebug("Directory was already removed: {Directory}", path);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to remove empty directory: {Directory}", path);
            }
        }
        catch (DirectoryNotFoundException)
        {
            _logger.LogDebug("Root directory no longer exists: {Directory}", path);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error during directory cleanup: {Directory}", path);
        }
    }

    private void LogFailedFiles(List<(string FilePath, Exception Exception)> failedFiles)
    {
        _logger.LogWarning("The following files failed to process:");

        foreach (var (filePath, exception) in failedFiles.Take(10))
            _logger.LogWarning("- {FilePath}: {ErrorMessage}", filePath, exception.Message);

        if (failedFiles.Count > 10)
            _logger.LogWarning("... and {AdditionalFailures} more files failed", failedFiles.Count - 10);
    }
}