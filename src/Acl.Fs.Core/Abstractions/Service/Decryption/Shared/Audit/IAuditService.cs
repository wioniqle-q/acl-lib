namespace Acl.Fs.Core.Abstractions.Service.Decryption.Shared.Audit;

internal interface IAuditService
{
    Task AuditDecryptionStarted(string algorithm, CancellationToken cancellationToken);
    Task AuditInputStreamOpened(string path, CancellationToken cancellationToken);
    Task AuditOutputStreamOpened(string path, CancellationToken cancellationToken);
    Task AuditHeaderRead(CancellationToken cancellationToken);
    Task AuditDecryptionCompleted(CancellationToken cancellationToken);
    Task AuditDecryptionFailed(Exception ex, CancellationToken cancellationToken);
    Task AuditBlockDecryptionFailed(long blockIndex, Exception ex, CancellationToken cancellationToken);
}