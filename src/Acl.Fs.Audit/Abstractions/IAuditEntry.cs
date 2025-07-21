using System.Collections.Frozen;

namespace Acl.Fs.Audit.Abstractions;

internal interface IAuditEntry
{
    DateTimeOffset TimestampUtc { get; }
    string Category { get; }
    string Message { get; }
    int EventId { get; }
    FrozenDictionary<string, object?> DiagnosticContext { get; }
}