namespace Acl.Fs.Cli.Abstractions.Services;

internal interface IOperationExecutor
{
    Task<bool> ExecuteEncryptionAsync(string sourceFolder, string destinationFolder, string password);
    Task<bool> ExecuteDecryptionAsync(string encryptedFolder, string decryptedFolder, string password);
}