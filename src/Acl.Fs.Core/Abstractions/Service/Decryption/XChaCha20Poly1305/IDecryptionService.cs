using Acl.Fs.Core.Models.XChaCha20Poly1305;
using FileTransferInstruction = Acl.Fs.Core.Models.FileTransferInstruction;

namespace Acl.Fs.Core.Abstractions.Service.Decryption.XChaCha20Poly1305;

public interface IDecryptionService
{
    Task DecryptFileAsync(
        FileTransferInstruction transferInstruction,
        XChaCha20Poly1305DecryptionInput input,
        CancellationToken cancellationToken);
}