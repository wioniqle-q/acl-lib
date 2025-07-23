using System.CommandLine;
using Acl.Fs.Cli.Abstractions.Services;

namespace Acl.Fs.Cli.Services;

internal sealed class CommandService(IOperationExecutor operationExecutor, ILoggingService loggingService)
    : ICommandService
{
    private readonly ILoggingService _loggingService = loggingService
                                                       ?? throw new ArgumentNullException(nameof(loggingService));

    private readonly IOperationExecutor _operationExecutor = operationExecutor
                                                             ?? throw new ArgumentNullException(
                                                                 nameof(operationExecutor));

    public RootCommand CreateRootCommand()
    {
        var rootCommand = new RootCommand("XChaCha20Poly1305 File Encryption/Decryption CLI");

        var encryptedFolderOption = new Option<string>(
            ["--encrypted-folder", "-e"],
            "Path to the encrypted files folder")
        {
            IsRequired = false
        };

        var decryptedFolderOption = new Option<string>(
            ["--decrypted-folder", "-d"],
            "Path to the decrypted files folder")
        {
            IsRequired = false
        };

        var passwordOption = new Option<string>(
            ["--password", "-p"],
            "Password for encryption/decryption")
        {
            IsRequired = true
        };

        rootCommand.AddGlobalOption(encryptedFolderOption);
        rootCommand.AddGlobalOption(decryptedFolderOption);
        rootCommand.AddGlobalOption(passwordOption);

        var encryptCommand = CreateEncryptCommand(encryptedFolderOption, decryptedFolderOption, passwordOption);
        var decryptCommand = CreateDecryptCommand(encryptedFolderOption, decryptedFolderOption, passwordOption);

        rootCommand.AddCommand(encryptCommand);
        rootCommand.AddCommand(decryptCommand);

        return rootCommand;
    }

    private Command CreateEncryptCommand(
        Option<string> encryptedFolderOption,
        Option<string> decryptedFolderOption,
        Option<string> passwordOption)
    {
        var encryptCommand = new Command("encrypt", "Encrypt files from decrypted folder to encrypted folder");

        encryptCommand.SetHandler(async (encryptedFolder, decryptedFolder, password) =>
        {
            if (string.IsNullOrEmpty(decryptedFolder))
            {
                Console.WriteLine("Error: --decrypted-folder is required for encryption");
                return;
            }

            if (string.IsNullOrEmpty(encryptedFolder))
            {
                Console.WriteLine("Error: --encrypted-folder is required for encryption");
                return;
            }

            var success = await _operationExecutor.ExecuteEncryptionAsync(decryptedFolder, encryptedFolder, password);
            if (success is not true) Environment.ExitCode = 1;

            await _loggingService.FlushAndCloseAsync();
        }, decryptedFolderOption, encryptedFolderOption, passwordOption);

        return encryptCommand;
    }

    private Command CreateDecryptCommand(
        Option<string> encryptedFolderOption,
        Option<string> decryptedFolderOption,
        Option<string> passwordOption)
    {
        var decryptCommand = new Command("decrypt", "Decrypt files from encrypted folder to decrypted folder");

        decryptCommand.SetHandler(async (encryptedFolder, decryptedFolder, password) =>
        {
            if (string.IsNullOrEmpty(encryptedFolder))
            {
                Console.WriteLine("Error: --encrypted-folder is required for decryption");
                return;
            }

            if (string.IsNullOrEmpty(decryptedFolder))
            {
                Console.WriteLine("Error: --decrypted-folder is required for decryption");
                return;
            }

            var success = await _operationExecutor.ExecuteDecryptionAsync(encryptedFolder, decryptedFolder, password);
            if (success is not true) Environment.ExitCode = 1;

            await _loggingService.FlushAndCloseAsync();
        }, encryptedFolderOption, decryptedFolderOption, passwordOption);

        return decryptCommand;
    }
}