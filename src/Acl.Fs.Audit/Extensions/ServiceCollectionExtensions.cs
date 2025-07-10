using Acl.Fs.Audit.Abstractions;
using Acl.Fs.Audit.Implementations;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Acl.Fs.Audit.Extensions;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddAuditLogger(this IServiceCollection services)
    {
        services.TryAddSingleton<IAuditLogger, DefaultAuditLogger>();
        return services;
    }
}