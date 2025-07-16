namespace Acl.Fs.Core.Abstractions.Service.Encryption.Shared.Audit;

internal interface IAuditService
{
    Task AuditEncryptionStarted(string algorithm, CancellationToken cancellationToken);
    Task AuditInputStreamOpened(string inputPath, CancellationToken cancellationToken);
    Task AuditOutputStreamOpened(string outputPath, CancellationToken cancellationToken);
    Task AuditHeaderPrepared(CancellationToken cancellationToken);
    Task AuditHeaderWritten(CancellationToken cancellationToken);
    Task AuditEncryptionCompleted(CancellationToken cancellationToken);
    Task AuditEncryptionFailed(Exception exception, CancellationToken cancellationToken);
    Task AuditBlockEncryptionFailed(long blockIndex, Exception exception, CancellationToken cancellationToken);

    Task AuditFileReadConsistency(long totalBytesRead, System.IO.Stream sourceStream,
        CancellationToken cancellationToken);
}