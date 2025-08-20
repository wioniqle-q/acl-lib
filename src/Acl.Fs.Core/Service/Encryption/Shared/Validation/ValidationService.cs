using Acl.Fs.Core.Abstractions.Service.Encryption.Shared.Audit;
using Acl.Fs.Core.Abstractions.Service.Encryption.Shared.Validation;

namespace Acl.Fs.Core.Service.Encryption.Shared.Validation;

internal sealed class ValidationService(IAuditService auditService) : IValidationService
{
    private readonly IAuditService
        _auditService = auditService ?? throw new ArgumentNullException(nameof(auditService));

    public async Task ValidateFileReadConsistencyAsync(long totalBytesRead, System.IO.Stream sourceStream,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (totalBytesRead == sourceStream.Length)
            return;

        await _auditService.AuditFileReadConsistency(totalBytesRead, sourceStream, cancellationToken);

        throw new InvalidOperationException();
    }
}