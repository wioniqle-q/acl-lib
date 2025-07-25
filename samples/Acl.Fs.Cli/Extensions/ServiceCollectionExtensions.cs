using Acl.Fs.Cli.Abstractions.Services;
using Acl.Fs.Cli.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Serilog;

namespace Acl.Fs.Cli.Extensions;

internal static class ServiceCollectionExtensions
{
    public static IServiceCollection AddCliServices(this IServiceCollection services)
    {
        services.AddSingleton<ILoggingService, LoggingService>();
        services.AddSingleton<IGlobalCancellationManager, GlobalCancellationManager>();
        services.AddScoped<IOperationExecutor, OperationExecutor>();
        services.AddScoped<ICommandService, CommandService>();
        services.AddScoped<FileOperationValidator>();
        services.AddScoped<IOperationResultHandler, OperationResultHandler>();

        return services;
    }

    public static IServiceCollection AddSerilogLogging(this IServiceCollection services, string logsDirectory)
    {
        var loggingService = new LoggingService();
        loggingService.ConfigureGlobalLogger(logsDirectory);

        services.AddSingleton<ILoggingService>(loggingService);
        services.AddLogging(configure =>
        {
            configure.ClearProviders();
            configure.AddSerilog(Log.Logger, true);
        });

        return services;
    }
}