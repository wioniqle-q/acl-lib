using Acl.Fs.Core.Models.AesGcm;
using FileTransferInstruction = Acl.Fs.Core.Models.FileTransferInstruction;

namespace Acl.Fs.Core.Abstractions.Service.Decryption.AesGcm;

public interface IDecryptionService
{
    Task DecryptFileAsync(
        FileTransferInstruction transferInstruction,
        AesDecryptionInput input,
        CancellationToken cancellationToken);
}