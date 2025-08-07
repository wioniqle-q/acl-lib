namespace Acl.Fs.Cli.Models;

internal class OperationResult
{
    public int SuccessCount { get; init; }
    public int FailureCount { get; init; }
    public int ProcessedCount { get; init; }
    public int TotalCount { get; init; }
    public List<(string FilePath, Exception Exception)> FailedFiles { get; init; } = [];
    public bool WasStoppedEarly { get; init; }
    public string? StopReason { get; init; }
    public bool IsPartialSuccess => SuccessCount > 0 && FailureCount > 0;
    public bool IsCompleteFailure => SuccessCount is 0 && ProcessedCount > 0;
}