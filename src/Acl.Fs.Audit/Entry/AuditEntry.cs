using System.Collections.Frozen;
using Acl.Fs.Audit.Abstractions;

namespace Acl.Fs.Audit.Entry;

internal readonly struct AuditEntry(
    DateTimeOffset timestampUtc,
    string category,
    string message,
    int eventId = 0,
    FrozenDictionary<string, object?>? diagnosticContext = null)
    : IAuditEntry
{
    public DateTimeOffset TimestampUtc { get; } = timestampUtc;
    public string Category { get; } = category;
    public string Message { get; } = message;
    public int EventId { get; } = eventId;

    public FrozenDictionary<string, object?> DiagnosticContext { get; } =
        diagnosticContext ?? FrozenDictionary<string, object?>.Empty;
}