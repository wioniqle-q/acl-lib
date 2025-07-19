using Acl.Fs.Audit.Abstractions;
using Microsoft.Extensions.Logging;

namespace Acl.Fs.Audit.Implementation;

internal sealed class DefaultAuditLogger(ILogger<DefaultAuditLogger> logger) : IAuditLogger
{
    public ValueTask LogAsync(IAuditEntry entry, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var diagnosticContextStr = entry.DiagnosticContext is { Count: > 0 }
            ? string.Join(", ", entry.DiagnosticContext.Select(kv => $"{kv.Key}={kv.Value}"))
            : "";

        logger.LogInformation(
            "[AUDIT] {TimestampUtc} {Category} {EventId}: {Message} {DiagnosticContext}",
            entry.TimestampUtc.ToString("O"),
            entry.Category,
            entry.EventId,
            entry.Message,
            diagnosticContextStr);
        return ValueTask.CompletedTask;
    }
}