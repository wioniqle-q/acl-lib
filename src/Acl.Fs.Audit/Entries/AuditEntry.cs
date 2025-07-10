using Acl.Fs.Audit.Abstractions;

namespace Acl.Fs.Audit.Entries;

internal readonly struct AuditEntry(
    DateTimeOffset timestampUtc,
    string category,
    string message,
    int eventId = 0,
    IReadOnlyDictionary<string, object?>? diagnosticContext = null)
    : IAuditEntry
{
    public DateTimeOffset TimestampUtc { get; } = timestampUtc;
    public string Category { get; } = category;
    public string Message { get; } = message;
    public int EventId { get; } = eventId;

    public IReadOnlyDictionary<string, object?> DiagnosticContext { get; } =
        diagnosticContext ?? new Dictionary<string, object?>();
}