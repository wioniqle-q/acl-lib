using Acl.Fs.Cli.Configuration;

namespace Acl.Fs.Cli.Abstractions.Services;

internal interface IFileOperationValidator
{
    void ValidateFileOperation(string sourceFilePath, string destinationPath, CryptoSettings settings,
        bool isEncryption = false);

    void CleanupFailedOperation(string destinationPath, string? protectedRootPath = null);
}