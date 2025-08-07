namespace Acl.Fs.Cli.Abstractions.Services;

internal interface ICryptoService : IDisposable
{
    Task EncryptFolderAsync(string sourceFolder, string destinationFolder, ReadOnlyMemory<byte> password,
        CancellationToken cancellationToken = default);

    Task DecryptFolderAsync(string encryptedFolder, string decryptedFolder, ReadOnlyMemory<byte> password,
        CancellationToken cancellationToken = default);
}