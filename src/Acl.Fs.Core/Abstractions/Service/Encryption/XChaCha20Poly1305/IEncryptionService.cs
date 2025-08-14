using Acl.Fs.Core.Models.XChaCha20Poly1305;
using FileTransferInstruction = Acl.Fs.Core.Models.FileTransferInstruction;

namespace Acl.Fs.Core.Abstractions.Service.Encryption.XChaCha20Poly1305;

public interface IEncryptionService
{
    Task EncryptFileAsync(
        FileTransferInstruction transferInstruction,
        XChaCha20Poly1305EncryptionInput input,
        CancellationToken cancellationToken);
}