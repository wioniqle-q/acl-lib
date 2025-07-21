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
}