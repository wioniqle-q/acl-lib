using Acl.Fs.Core.Models.AesGcm;
using FileTransferInstruction = Acl.Fs.Core.Models.FileTransferInstruction;

namespace Acl.Fs.Core.Abstractions.Service.Encryption.AesGcm;

public interface IEncryptionService
{
    Task EncryptFileAsync(
        FileTransferInstruction transferInstruction,
        AesEncryptionInput input,
        CancellationToken cancellationToken);
}