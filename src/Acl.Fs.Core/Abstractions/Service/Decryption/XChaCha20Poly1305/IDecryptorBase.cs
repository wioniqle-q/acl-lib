﻿using Acl.Fs.Core.Models;
using Microsoft.Extensions.Logging;

namespace Acl.Fs.Core.Abstractions.Service.Decryption.XChaCha20Poly1305;

internal interface IDecryptorBase
{
    Task ExecuteDecryptionProcessAsync(
        FileTransferInstruction instruction,
        byte[] key,
        ILogger logger,
        CancellationToken cancellationToken);
}