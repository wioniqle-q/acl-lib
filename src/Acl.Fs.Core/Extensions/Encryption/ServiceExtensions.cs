using System.Security.Cryptography;
using Acl.Fs.Core.Abstractions.Factory;
using Acl.Fs.Core.Abstractions.Service.Encryption.AesGcm;
using Acl.Fs.Core.Abstractions.Service.Encryption.Shared.Audit;
using Acl.Fs.Core.Abstractions.Service.Encryption.Shared.Metadata;
using Acl.Fs.Core.Abstractions.Service.Encryption.Shared.Processor;
using Acl.Fs.Core.Abstractions.Service.Encryption.Shared.Validation;
using Acl.Fs.Core.Factory;
using Acl.Fs.Core.Service.Encryption.AesGcm;
using Acl.Fs.Core.Service.Encryption.Shared.Audit;
using Acl.Fs.Core.Service.Encryption.Shared.Metadata;
using Acl.Fs.Core.Service.Encryption.Shared.Processor;
using Acl.Fs.Core.Service.Encryption.Shared.Provider;
using Acl.Fs.Core.Service.Encryption.Shared.Validation;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using NSec.Cryptography;
using ChaCha20Poly1305 = System.Security.Cryptography.ChaCha20Poly1305;

namespace Acl.Fs.Core.Extensions.Encryption;

public static class ServiceExtensions
{
    public static IServiceCollection AddEncryptionComponents(this IServiceCollection services)
    {
        services.TryAddScoped(typeof(IBlockProcessor<>), typeof(BlockProcessor<>));
        services.TryAddScoped<IValidationService, ValidationService>();
        services.TryAddScoped<IMetadataService, MetadataService>();
        services.TryAddScoped<IAuditService, AuditService>();

        return services;
    }

    public static IServiceCollection AddAesGcmEncryptionServices(this IServiceCollection services)
    {
        services.TryAddScoped<ICryptoProvider<AesGcm>, AesGcmCryptoProvider>();
        services.TryAddScoped<IBlockProcessor<AesGcm>, BlockProcessor<AesGcm>>();

        services.TryAddScoped<IEncryptorBase, EncryptorBase>();
        services.TryAddScoped<IEncryptionService, EncryptionService>();

        return services;
    }

    public static IServiceCollection AddChaCha20Poly1305EncryptionServices(this IServiceCollection services)
    {
        services.TryAddScoped<ICryptoProvider<ChaCha20Poly1305>, ChaCha20Poly1305CryptoProvider>();
        services.TryAddScoped<IBlockProcessor<ChaCha20Poly1305>, BlockProcessor<ChaCha20Poly1305>>();

        services
            .TryAddScoped<Abstractions.Service.Encryption.ChaCha20Poly1305.IEncryptorBase,
                Service.Encryption.ChaCha20Poly1305.EncryptorBase>();
        services
            .TryAddScoped<Abstractions.Service.Encryption.ChaCha20Poly1305.IEncryptionService,
                Service.Encryption.ChaCha20Poly1305.EncryptionService>();

        return services;
    }

    public static IServiceCollection AddXChaCha20Poly1305EncryptionServices(this IServiceCollection services)
    {
        services.TryAddScoped<IXChaCha20Poly1305Factory, XChaCha20Poly1305Factory>();
        services.TryAddScoped<ICryptoProvider<Key>, XChaCha20Poly1305CryptoProvider>();
        services.TryAddScoped<IBlockProcessor<Key>, BlockProcessor<Key>>();

        services
            .TryAddScoped<Abstractions.Service.Encryption.XChaCha20Poly1305.IEncryptorBase,
                Service.Encryption.XChaCha20Poly1305.EncryptorBase>();
        services
            .TryAddScoped<Abstractions.Service.Encryption.XChaCha20Poly1305.IEncryptionService,
                Service.Encryption.XChaCha20Poly1305.EncryptionService>();

        return services;
    }
}