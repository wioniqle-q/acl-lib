﻿namespace Acl.Fs.Cli.Models;

internal class OperationRequest
{
    public required string[] Files { get; init; }
    public required Func<string, CancellationToken, Task> ProcessFileAsync { get; init; }
    public required CancellationToken CancellationToken { get; init; }
    public required string OperationName { get; init; }
    public string? CleanupPath { get; init; }

    public int MaxConsecutiveFailures { get; init; } = 4;
    public double MaxFailureRatio { get; init; } = 0.8;
    public int MinFilesBeforeRatioCheck { get; init; } = 2;
}