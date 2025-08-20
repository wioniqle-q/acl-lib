using System.Security.Cryptography;
using Acl.Fs.Core.Abstractions.Service.Encryption.ChaCha20Poly1305;
using Acl.Fs.Core.Models.ChaCha20Poly1305;
using Acl.Fs.Core.Pool;
using Microsoft.Extensions.Logging;
using FileTransferInstruction = Acl.Fs.Core.Models.FileTransferInstruction;
using static Acl.Fs.Constant.Cryptography.CryptoConstants;

namespace Acl.Fs.Core.Service.Encryption.ChaCha20Poly1305;

internal sealed class EncryptionService(
    ILogger<EncryptionService> logger,
    IEncryptorBase encryptorBase)
    : IEncryptionService
{
    private readonly IEncryptorBase _encryptorBase =
        encryptorBase ?? throw new ArgumentNullException(nameof(encryptorBase));

    private readonly ILogger<EncryptionService> _logger =
        logger ?? throw new ArgumentNullException(nameof(logger));

    public async Task EncryptFileAsync(
        FileTransferInstruction transferInstruction,
        ChaCha20Poly1305EncryptionInput input,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var nonceBuffer = CryptoPool.Rent(NonceSize);

        try
        {
            RandomNumberGenerator.Fill(nonceBuffer.AsSpan(0, NonceSize));

            await _encryptorBase.ExecuteEncryptionProcessAsync(
                transferInstruction,
                input.Password,
                nonceBuffer.AsMemory(0, NonceSize),
                _logger,
                cancellationToken);
        }
        finally
        {
            CryptoPool.Return(nonceBuffer);
        }
    }
}