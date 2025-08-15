using Acl.Fs.Core.Models;
using Microsoft.Extensions.Logging;

namespace Acl.Fs.Core.Abstractions.Service.Decryption.ChaCha20Poly1305;

internal interface IDecryptorBase
{
    Task ExecuteDecryptionProcessAsync(
        FileTransferInstruction instruction,
        ReadOnlyMemory<byte> password,
        ILogger logger,
        CancellationToken cancellationToken);
}