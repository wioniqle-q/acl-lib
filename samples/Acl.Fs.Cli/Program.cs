using Acl.Fs.Audit.Extensions;
using Acl.Fs.Cli.Abstractions.Services;
using Acl.Fs.Cli.Configuration;
using Acl.Fs.Cli.Extensions;
using Acl.Fs.Cli.Services;
using Acl.Fs.Core.Extensions;
using Acl.Fs.Core.Extensions.Decryption;
using Acl.Fs.Core.Extensions.Encryption;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Acl.Fs.Cli;

internal sealed class Program
{
    private static async Task<int> Main(string[] args)
    {
        var host = CreateHost(args);

        using var scope = host.Services.CreateScope();
        var commandService = scope.ServiceProvider.GetRequiredService<ICommandService>();

        var rootCommand = commandService.CreateRootCommand();
        var parseResult = rootCommand.Parse(args);

        /*
        string[] argsManuelEncrypt =
        [
            "encrypt",
            "--source", @"",
            "--destination", @"",
            "--password", ""
        ];

        var encryptionParseResult = rootCommand.Parse(argsManuelEncrypt);
        return await parseResult.InvokeAsync(encryptionParseResult);
        */

        /*
        string[] argsManuelDecrypt =
        [
            "decrypt",
            "--source", @"",
            "--destination", @"",
            "--password", ""
        ];

        var decryptionParseResult = rootCommand.Parse(argsManuelDecrypt);
        return await parseResult.InvokeAsync(decryptionParseResult);
        */

        return await parseResult.InvokeAsync();
    }

    private static IHost CreateHost(string[] args)
    {
        var exeDirectory = Path.GetDirectoryName(Environment.ProcessPath) ?? Environment.CurrentDirectory;
        var logsDirectory = Path.Combine(exeDirectory, "acl-logs");

        var builder = Host.CreateApplicationBuilder(args);

        builder.Configuration.AddJsonFile("appsettings.json", true, true);
        builder.Services.Configure<CryptoSettings>(builder.Configuration.GetSection("CryptoSettings"));

        builder.Services.AddSerilogLogging(logsDirectory);

        builder.Services.AddAclFsCore();
        builder.Services.AddXChaCha20Poly1305Factory();
        builder.Services.AddXChaCha20Poly1305EncryptionServices();
        builder.Services.AddXChaCha20Poly1305DecryptionServices();
        builder.Services.AddDecryptionComponents();
        builder.Services.AddEncryptionComponents();
        builder.Services.AddAuditLogger();

        builder.Services.AddScoped<ICryptoService, CryptoService>();
        builder.Services.AddCliServices();

        return builder.Build();
    }
}