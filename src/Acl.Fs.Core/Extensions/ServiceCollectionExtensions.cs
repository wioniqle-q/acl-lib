using Acl.Fs.Core.Abstractions;
using Acl.Fs.Core.Abstractions.Factory;
using Acl.Fs.Core.Factory;
using Acl.Fs.Core.Policy;
using Acl.Fs.Core.Versioning;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Acl.Fs.Core.Extensions;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddAclFsCore(this IServiceCollection services)
    {
#if ALLOW_ALIGNMENT_POLICY
        services.TryAddScoped<IAlignmentPolicy, AlignedPolicy>(); // Experimental
#else
        services.TryAddScoped<IAlignmentPolicy, UnalignedPolicy>(); // Production
#endif

        services.TryAddSingleton<IFileVersionValidator, FileVersionValidator>();

        return services;
    }

    public static IServiceCollection AddAesGcmFactory(this IServiceCollection services)
    {
        services.TryAddSingleton<IAesGcmFactory, AesGcmFactory>();

        return services;
    }

    public static IServiceCollection AddChaCha20Poly1305Factory(this IServiceCollection services)
    {
        services.TryAddSingleton<IChaCha20Poly1305Factory, ChaCha20Poly1305Factory>();

        return services;
    }
}