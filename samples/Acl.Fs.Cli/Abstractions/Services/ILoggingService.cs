using Serilog;

namespace Acl.Fs.Cli.Abstractions.Services;

internal interface ILoggingService
{
    void ConfigureGlobalLogger(string logsDirectory);
    ILogger CreateOperationLogger(string operationType, string operationId);
    Task FlushAndCloseAsync();
}