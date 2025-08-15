using Acl.Fs.Core.Models;
using Microsoft.Extensions.Logging;

namespace Acl.Fs.Core.Abstractions.Service.Encryption.XChaCha20Poly1305;

internal interface IEncryptorBase
{
    Task ExecuteEncryptionProcessAsync(
        FileTransferInstruction instruction,
        ReadOnlyMemory<byte> password,
        ReadOnlyMemory<byte> nonce,
        ILogger logger,
        CancellationToken cancellationToken);
}