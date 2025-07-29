using Acl.Fs.Core.Models;
using Microsoft.Extensions.Logging;

namespace Acl.Fs.Core.Abstractions.Service.Encryption.AesGcm;

internal interface IEncryptorBase
{
    Task ExecuteEncryptionProcessAsync(
        FileTransferInstruction instruction,
        byte[] key,
        byte[] nonce,
        ILogger logger,
        CancellationToken cancellationToken);
}