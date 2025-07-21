using System.CommandLine;

namespace Acl.Fs.Cli.Abstractions.Services;

internal interface ICommandService
{
    RootCommand CreateRootCommand();
}