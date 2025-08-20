using System.Collections.Frozen;
using Acl.Fs.Audit.Abstractions;
using Acl.Fs.Audit.Category;
using Acl.Fs.Audit.Constant;
using Acl.Fs.Audit.Extensions;
using Acl.Fs.Core.Abstractions.Service.Decryption.Shared.Audit;
using Acl.Fs.Core.Resource;

namespace Acl.Fs.Core.Service.Decryption.Shared.Audit;

internal sealed class AuditService(IAuditLogger auditLogger) : IAuditService
{
    private readonly IAuditLogger _auditLogger = auditLogger ?? throw new ArgumentNullException(nameof(auditLogger));

    public async Task AuditDecryptionStarted(string algorithm, CancellationToken cancellationToken)
    {
        await _auditLogger.AuditAsync(
            AuditCategory.CryptoIntegrity,
            AuditMessages.DecryptionProcessStarted,
            AuditEventIds.DecryptionStarted,
            new Dictionary<string, object?> { { AuditMessages.ContextKeys.Algorithm, algorithm } }
                .ToFrozenDictionary(),
            cancellationToken);
    }

    public async Task AuditInputStreamOpened(string path, CancellationToken cancellationToken)
    {
        await _auditLogger.AuditAsync(
            AuditCategory.FileAccess,
            AuditMessages.InputStreamOpened,
            AuditEventIds.DecryptionInputOpened,
            new Dictionary<string, object?> { { AuditMessages.ContextKeys.InputFile, path } }.ToFrozenDictionary(),
            cancellationToken);
    }

    public async Task AuditOutputStreamOpened(string path, CancellationToken cancellationToken)
    {
        await _auditLogger.AuditAsync(
            AuditCategory.FileAccess,
            AuditMessages.OutputStreamOpened,
            AuditEventIds.DecryptionOutputOpened,
            new Dictionary<string, object?> { { AuditMessages.ContextKeys.OutputFile, path } }.ToFrozenDictionary(),
            cancellationToken);
    }

    public async Task AuditHeaderRead(CancellationToken cancellationToken)
    {
        await _auditLogger.AuditAsync(
            AuditCategory.CryptoIntegrity,
            AuditMessages.DecryptionHeaderRead,
            AuditEventIds.DecryptionHeaderRead,
            cancellationToken: cancellationToken);
    }

    public async Task AuditDecryptionCompleted(CancellationToken cancellationToken)
    {
        await _auditLogger.AuditAsync(
            AuditCategory.CryptoIntegrity,
            AuditMessages.DecryptionProcessCompleted,
            AuditEventIds.DecryptionCompleted,
            cancellationToken: cancellationToken);
    }

    public async Task AuditDecryptionFailed(Exception ex, CancellationToken cancellationToken)
    {
        await _auditLogger.AuditAsync(
            AuditCategory.CryptoIntegrity,
            AuditMessages.DecryptionFailed,
            AuditEventIds.DecryptionError,
            new Dictionary<string, object?>
            {
                { AuditMessages.ContextKeys.ExceptionType, ex.GetType().Name },
                { AuditMessages.ContextKeys.ExceptionMessage, ex.Message },
                { AuditMessages.ContextKeys.StackTrace, ex.StackTrace }
            }.ToFrozenDictionary(),
            cancellationToken);
    }

    public async Task AuditBlockDecryptionFailed(long blockIndex, Exception ex, CancellationToken cancellationToken)
    {
        await _auditLogger.AuditAsync(
            AuditCategory.CryptoIntegrity,
            AuditMessages.BlockDecryptionFailed,
            AuditEventIds.BlockDecryptionFailed,
            new Dictionary<string, object?>
            {
                { AuditMessages.ContextKeys.BlockIndex, blockIndex },
                { AuditMessages.ContextKeys.ExceptionType, ex.GetType().Name },
                { AuditMessages.ContextKeys.ExceptionMessage, ex.Message },
                { AuditMessages.ContextKeys.StackTrace, ex.StackTrace }
            }.ToFrozenDictionary(),
            cancellationToken);
    }
}