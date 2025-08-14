namespace Acl.Fs.Core.Abstractions.Service.Encryption.Shared.Validation;

internal interface IValidationService
{
    Task ValidateFileReadConsistencyAsync(long totalBytesRead, System.IO.Stream sourceStream,
        CancellationToken cancellationToken);
}