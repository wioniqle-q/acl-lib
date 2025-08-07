using Acl.Fs.Cli.Abstractions.Services;
using Serilog;
using Serilog.Events;

namespace Acl.Fs.Cli.Services;

internal sealed class LoggingService : ILoggingService
{
    private const string LogTemplate =
        "{Timestamp:yyyy-MM-dd HH:mm:ss.fff} UTC [{Level:u3}] {Message:lj}{NewLine}{Exception}";

    public void ConfigureGlobalLogger(string logsDirectory)
    {
        Directory.CreateDirectory(logsDirectory);

        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Debug()
            .MinimumLevel.Override("Microsoft", LogEventLevel.Information)
            .MinimumLevel.Override("System", LogEventLevel.Information)
            .Enrich.FromLogContext()
            .WriteTo.Console(outputTemplate: LogTemplate)
            .WriteTo.File(
                Path.Combine(logsDirectory, "acl-operations-.log"),
                rollingInterval: RollingInterval.Day,
                retainedFileCountLimit: 30,
                outputTemplate: LogTemplate,
                shared: true)
            .CreateLogger();
    }

    public ILogger CreateOperationLogger(string operationType, string operationId)
    {
        var exeDirectory = Path.GetDirectoryName(Environment.ProcessPath) ?? Environment.CurrentDirectory;
        var logsDirectory = Path.Combine(exeDirectory, "acl-logs");
        var operationLogFile = Path.Combine(logsDirectory, $"{operationType}-{operationId}.log");

        return new LoggerConfiguration()
            .WriteTo.File(operationLogFile, outputTemplate: LogTemplate)
            .CreateLogger();
    }

    public async Task FlushAndCloseAsync()
    {
        await Log.CloseAndFlushAsync();
    }
}