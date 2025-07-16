using System.Security.Cryptography;
using Acl.Fs.Core.Abstractions.Service.Decryption.AesGcm;
using Acl.Fs.Core.Models.AesGcm;
using Microsoft.Extensions.Logging;
using FileTransferInstruction = Acl.Fs.Core.Models.FileTransferInstruction;

namespace Acl.Fs.Core.Service.Decryption.AesGcm;

internal sealed class DecryptionService(
    ILogger<DecryptionService> logger,
    IDecryptorBase decryptorBase)
    : IDecryptionService
{
    private readonly IDecryptorBase _decryptorBase =
        decryptorBase ?? throw new ArgumentNullException(nameof(decryptorBase));

    private readonly ILogger<DecryptionService> _logger = logger ?? throw new ArgumentNullException(nameof(logger));

    public async Task DecryptFileAsync(
        FileTransferInstruction transferInstruction,
        AesDecryptionInput input,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            await _decryptorBase.ExecuteDecryptionProcessAsync(
                transferInstruction, input.DecryptionKey.Span.ToArray(), _logger, cancellationToken);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input.DecryptionKey.Span.ToArray());
        }
    }
}