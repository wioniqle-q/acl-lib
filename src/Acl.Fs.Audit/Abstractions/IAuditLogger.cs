namespace Acl.Fs.Audit.Abstractions;

internal interface IAuditLogger
{
    ValueTask LogAsync(IAuditEntry entry, CancellationToken cancellationToken = default);
}