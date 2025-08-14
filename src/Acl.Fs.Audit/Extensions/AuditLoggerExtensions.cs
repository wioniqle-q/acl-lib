using System.Collections.Frozen;
using Acl.Fs.Audit.Abstractions;
using Acl.Fs.Audit.Entry;

namespace Acl.Fs.Audit.Extensions;

internal static class AuditLoggerExtensions
{
    internal static ValueTask AuditAsync(this IAuditLogger logger,
        string category,
        string message,
        int eventId = 0,
        FrozenDictionary<string, object?>? diagnosticContext = null,
        CancellationToken cancellationToken = default)
    {
        var entry = new AuditEntry(DateTimeOffset.UtcNow, category, message, eventId, diagnosticContext);
        return logger.LogAsync(entry, cancellationToken);
    }

    internal static void Audit(this IAuditLogger logger,
        string category,
        string message,
        int eventId = 0,
        FrozenDictionary<string, object?>? diagnosticContext = null)
    {
        var entry = new AuditEntry(DateTimeOffset.UtcNow, category, message, eventId, diagnosticContext);
        var task = logger.LogAsync(entry, CancellationToken.None);

        if (task.IsCompleted is not true) _ = Task.Run(async () => { await task.ConfigureAwait(false); });
    }
}