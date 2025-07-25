using System.Collections.Concurrent;
using Acl.Fs.Cli.Abstractions.Services;
using Acl.Fs.Cli.Models;
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
        var successCount = 0;
        var failureCount = 0;
        var consecutiveFailures = 0;
        var processedCount = 0;

        var earlyStopCts = new CancellationTokenSource();
        var earlyStopToken = CancellationTokenSource.CreateLinkedTokenSource(
            request.CancellationToken, earlyStopCts.Token).Token;

        var stopReason = string.Empty;

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
                    (!(ex is OperationCanceledException && earlyStopToken.IsCancellationRequested))
                {
                    var currentFailureCount = Interlocked.Increment(ref failureCount);
                    var currentConsecutiveFailures = Interlocked.Increment(ref consecutiveFailures);
                    var currentProcessedCount = Interlocked.Increment(ref processedCount);

                    failedFiles.Add((file, ex));
                    _logger.LogError(ex, "Failed to process file: {FilePath}", file);

                    var shouldStop = CheckEarlyStopConditions(
                        request, currentConsecutiveFailures, currentFailureCount,
                        currentProcessedCount, out var reason);

                    if (shouldStop && earlyStopCts.Token.IsCancellationRequested is not true)
                    {
                        stopReason = reason;
                        _logger.LogWarning(
                            "Early stopping {OperationName}: {Reason}. Processed: {ProcessedCount}, Failed: {FailedCount}, Success: {SuccessCount}",
                            request.OperationName, reason, currentProcessedCount, currentFailureCount, successCount);

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
            earlyStopCts.Dispose();
        }

        var result = new OperationResult
        {
            SuccessCount = successCount,
            FailureCount = failureCount,
            ProcessedCount = processedCount,
            TotalCount = request.Files.Length,
            FailedFiles = failedFiles.ToList(),
            WasStoppedEarly = earlyStopCts.Token.IsCancellationRequested &&
                              request.CancellationToken.IsCancellationRequested is not true,
            StopReason = stopReason
        };

        await HandleResultAsync(result, request);
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

    private async Task HandleResultAsync(OperationResult result, OperationRequest request)
    {
        _logger.LogInformation(
            "{OperationName} completed. Success: {SuccessCount}/{TotalCount}, Failed: {FailedCount}, Processed: {ProcessedCount}",
            request.OperationName, result.SuccessCount, result.TotalCount, result.FailureCount, result.ProcessedCount);

        if (result.FailedFiles.Count > 0)
        {
            if (result.WasStoppedEarly)
            {
                await HandleEarlyStopCleanupAsync(request);

                throw new InvalidOperationException(
                    $"{request.OperationName} stopped early due to excessive failures. " +
                    $"This typically indicates an incorrect password or corrupted files. " +
                    $"Processed {result.ProcessedCount} files, {result.FailureCount} failed, {result.SuccessCount} succeeded.");
            }

            LogFailedFiles(result.FailedFiles);

            if (result.IsCompleteFailure)
                throw new InvalidOperationException(
                    $"All {result.ProcessedCount} processed files failed. Check the password and file integrity.");

            if (result.IsPartialSuccess)
                _logger.LogInformation(
                    "{OperationName} completed with partial success: {SuccessCount} files processed successfully, {FailedCount} files failed",
                    request.OperationName, result.SuccessCount, result.FailureCount);
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
                    Directory.Delete(request.CleanupPath, true);
                    _logger.LogInformation("Cleaned up destination folder: {CleanupPath}", request.CleanupPath);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to cleanup destination folder: {CleanupPath}", request.CleanupPath);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during cleanup process");
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