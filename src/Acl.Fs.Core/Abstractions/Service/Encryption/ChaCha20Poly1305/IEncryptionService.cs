using Acl.Fs.Core.Models.ChaCha20Poly1305;
using FileTransferInstruction = Acl.Fs.Core.Models.FileTransferInstruction;

namespace Acl.Fs.Core.Abstractions.Service.Encryption.ChaCha20Poly1305;

public interface IEncryptionService
{
    Task EncryptFileAsync(
        FileTransferInstruction transferInstruction,
        ChaCha20Poly1305EncryptionInput input,
        CancellationToken cancellationToken);
}