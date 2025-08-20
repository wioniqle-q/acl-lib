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

        var sourceOption = new Option<string>(
            "--source",
            "-s")
        {
            Required = true,
            Recursive = true
        };

        var destinationOption = new Option<string>(
            "--destination",
            "-d")
        {
            Required = true,
            Recursive = true
        };

        var passwordOption = new Option<string>("--password",
            "-pw")
        {
            Required = true,
            Recursive = true
        };

        rootCommand.Add(sourceOption);
        rootCommand.Add(destinationOption);
        rootCommand.Add(passwordOption);

        var encryptCommand = CreateEncryptCommand(sourceOption, destinationOption, passwordOption);
        var decryptCommand = CreateDecryptCommand(sourceOption, destinationOption, passwordOption);

        rootCommand.Subcommands.Add(encryptCommand);
        rootCommand.Subcommands.Add(decryptCommand);

        return rootCommand;
    }

    private Command CreateEncryptCommand(
        Option<string> sourceOption,
        Option<string> destinationOption,
        Option<string> passwordOption)
    {
        var encryptCommand = new Command("encrypt", "Encrypt files from source folder to destination folder");

        encryptCommand.Options.Add(sourceOption);
        encryptCommand.Options.Add(destinationOption);
        encryptCommand.Options.Add(passwordOption);

        encryptCommand.SetAction(async parseResult =>
        {
            var source = parseResult.GetRequiredValue(sourceOption);
            var destination = parseResult.GetRequiredValue(destinationOption);
            var password = parseResult.GetRequiredValue(passwordOption);

            var success = await _operationExecutor.ExecuteEncryptionAsync(source, destination, password);
            if (success is not true) Environment.ExitCode = 1;

            await _loggingService.FlushAndCloseAsync();
        });

        return encryptCommand;
    }

    private Command CreateDecryptCommand(
        Option<string> sourceOption,
        Option<string> destinationOption,
        Option<string> passwordOption)
    {
        var decryptCommand = new Command("decrypt", "Decrypt files from source folder to destination folder");

        decryptCommand.Options.Add(sourceOption);
        decryptCommand.Options.Add(destinationOption);
        decryptCommand.Options.Add(passwordOption);

        decryptCommand.SetAction(async parseResult =>
        {
            var source = parseResult.GetRequiredValue(sourceOption);
            var destination = parseResult.GetRequiredValue(destinationOption);
            var password = parseResult.GetRequiredValue(passwordOption);

            var success = await _operationExecutor.ExecuteDecryptionAsync(source, destination, password);
            if (success is not true) Environment.ExitCode = 1;

            await _loggingService.FlushAndCloseAsync();
        });

        return decryptCommand;
    }
}