using System.Collections.Frozen;
using Acl.Fs.Audit.Abstractions;
using Acl.Fs.Audit.Category;
using Acl.Fs.Audit.Constant;
using Acl.Fs.Audit.Extensions;
using Acl.Fs.Core.Abstractions.Service.Encryption.Shared.Audit;
using Acl.Fs.Core.Resource;

namespace Acl.Fs.Core.Service.Encryption.Shared.Audit;

internal sealed class AuditService(IAuditLogger auditLogger) : IAuditService
{
    private readonly IAuditLogger _auditLogger = auditLogger ?? throw new ArgumentNullException(nameof(auditLogger));

    public async Task AuditEncryptionStarted(string algorithm, CancellationToken cancellationToken)
    {
        await _auditLogger.AuditAsync(
            AuditCategory.CryptoIntegrity,
            AuditMessages.EncryptionProcessStarted,
            AuditEventIds.EncryptionStarted,
            new Dictionary<string, object?> { { AuditMessages.ContextKeys.Algorithm, algorithm } }.ToFrozenDictionary(),
            cancellationToken);
    }

    public async Task AuditInputStreamOpened(string inputPath, CancellationToken cancellationToken)
    {
        await _auditLogger.AuditAsync(
            AuditCategory.FileAccess,
            AuditMessages.InputStreamOpened,
            AuditEventIds.EncryptionInputOpened,
            new Dictionary<string, object?> { { AuditMessages.ContextKeys.InputFile, inputPath } }.ToFrozenDictionary(),
            cancellationToken);
    }

    public async Task AuditOutputStreamOpened(string outputPath, CancellationToken cancellationToken)
    {
        await _auditLogger.AuditAsync(
            AuditCategory.FileAccess,
            AuditMessages.OutputStreamOpened,
            AuditEventIds.EncryptionOutputOpened,
            new Dictionary<string, object?> { { AuditMessages.ContextKeys.OutputFile, outputPath } }
                .ToFrozenDictionary(),
            cancellationToken);
    }

    public async Task AuditHeaderPrepared(CancellationToken cancellationToken)
    {
        await _auditLogger.AuditAsync(
            AuditCategory.Header,
            AuditMessages.HeaderPrepared,
            AuditEventIds.EncryptionHeaderPrepared,
            cancellationToken: cancellationToken);
    }

    public async Task AuditHeaderWritten(CancellationToken cancellationToken)
    {
        await _auditLogger.AuditAsync(
            AuditCategory.Header,
            AuditMessages.HeaderWritten,
            AuditEventIds.EncryptionHeaderWritten,
            cancellationToken: cancellationToken);
    }

    public async Task AuditEncryptionCompleted(CancellationToken cancellationToken)
    {
        await _auditLogger.AuditAsync(
            AuditCategory.CryptoIntegrity,
            AuditMessages.EncryptionProcessCompleted,
            AuditEventIds.EncryptionCompleted,
            cancellationToken: cancellationToken);
    }

    public async Task AuditEncryptionFailed(Exception exception, CancellationToken cancellationToken)
    {
        await _auditLogger.AuditAsync(
            AuditCategory.CryptoIntegrity,
            AuditMessages.EncryptionFailed,
            AuditEventIds.EncryptionError,
            new Dictionary<string, object?>
            {
                { AuditMessages.ContextKeys.ExceptionType, exception.GetType().Name },
                { AuditMessages.ContextKeys.ExceptionMessage, exception.Message },
                { AuditMessages.ContextKeys.StackTrace, exception.StackTrace }
            }.ToFrozenDictionary(),
            cancellationToken);
    }

    public async Task AuditBlockEncryptionFailed(long blockIndex, Exception exception,
        CancellationToken cancellationToken)
    {
        await _auditLogger.AuditAsync(
            AuditCategory.CryptoIntegrity,
            AuditMessages.BlockEncryptionFailed,
            AuditEventIds.BlockEncryptionFailed,
            new Dictionary<string, object?>
            {
                { AuditMessages.ContextKeys.BlockIndex, blockIndex },
                { AuditMessages.ContextKeys.ExceptionType, exception.GetType().Name },
                { AuditMessages.ContextKeys.ExceptionMessage, exception.Message },
                { AuditMessages.ContextKeys.StackTrace, exception.StackTrace }
            }.ToFrozenDictionary(),
            cancellationToken);
    }

    public async Task AuditFileReadConsistency(long totalBytesRead, System.IO.Stream sourceStream,
        CancellationToken cancellationToken)
    {
        await _auditLogger.AuditAsync(
            AuditCategory.CryptoIntegrity,
            string.Format(AuditMessages.ConsistencyErrorAudit, totalBytesRead, sourceStream.Length),
            AuditEventIds.BlockEncryptionFailed,
            new Dictionary<string, object?>
            {
                { AuditMessages.ContextKeys.TotalBytesRead, totalBytesRead },
                { AuditMessages.ContextKeys.StreamLength, sourceStream.Length }
            }.ToFrozenDictionary(),
            cancellationToken);
    }
}