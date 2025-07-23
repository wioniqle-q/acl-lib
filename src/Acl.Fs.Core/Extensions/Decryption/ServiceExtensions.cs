using System.Security.Cryptography;
using Acl.Fs.Core.Abstractions.Factory;
using Acl.Fs.Core.Abstractions.Service.Decryption.AesGcm;
using Acl.Fs.Core.Abstractions.Service.Decryption.Shared.Audit;
using Acl.Fs.Core.Abstractions.Service.Decryption.Shared.Block;
using Acl.Fs.Core.Abstractions.Service.Decryption.Shared.Header;
using Acl.Fs.Core.Abstractions.Service.Decryption.Shared.Processor;
using Acl.Fs.Core.Abstractions.Service.Decryption.Shared.Validation;
using Acl.Fs.Core.Factory;
using Acl.Fs.Core.Service.Decryption.AesGcm;
using Acl.Fs.Core.Service.Decryption.Shared.Audit;
using Acl.Fs.Core.Service.Decryption.Shared.Block;
using Acl.Fs.Core.Service.Decryption.Shared.Header;
using Acl.Fs.Core.Service.Decryption.Shared.Processor;
using Acl.Fs.Core.Service.Decryption.Shared.Provider;
using Acl.Fs.Core.Service.Decryption.Shared.Validation;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using NSec.Cryptography;
using ChaCha20Poly1305 = System.Security.Cryptography.ChaCha20Poly1305;

namespace Acl.Fs.Core.Extensions.Decryption;

public static class ServiceExtensions
{
    public static IServiceCollection AddDecryptionComponents(this IServiceCollection services)
    {
        services.TryAddScoped(typeof(IBlockProcessor<>), typeof(BlockProcessor<>));
        services.TryAddScoped<IHeaderReader, HeaderReader>();
        services.TryAddScoped<IBlockReader, BlockReader>();
        services.TryAddScoped<IAuditService, AuditService>();
        services.TryAddScoped<IBlockValidator, BlockValidator>();

        return services;
    }

    public static IServiceCollection AddAesGcmDecryptionServices(this IServiceCollection services)
    {
        services.TryAddScoped<ICryptoProvider<AesGcm>, AesGcmCryptoProvider>();
        services.TryAddScoped<IBlockProcessor<AesGcm>, BlockProcessor<AesGcm>>();

        services.TryAddScoped<IDecryptorBase, DecryptorBase>();
        services.TryAddScoped<IDecryptionService, DecryptionService>();

        return services;
    }

    public static IServiceCollection AddChaCha20Poly1305DecryptionServices(this IServiceCollection services)
    {
        services.TryAddScoped<ICryptoProvider<ChaCha20Poly1305>, ChaCha20Poly1305CryptoProvider>();
        services.TryAddScoped<IBlockProcessor<ChaCha20Poly1305>, BlockProcessor<ChaCha20Poly1305>>();

        services
            .TryAddScoped<Abstractions.Service.Decryption.ChaCha20Poly1305.IDecryptorBase,
                Service.Decryption.ChaCha20Poly1305.DecryptorBase>();
        services
            .TryAddScoped<Abstractions.Service.Decryption.ChaCha20Poly1305.IDecryptionService,
                Service.Decryption.ChaCha20Poly1305.DecryptionService>();

        return services;
    }

    public static IServiceCollection AddXChaCha20Poly1305DecryptionServices(this IServiceCollection services)
    {
        services.TryAddScoped<IXChaCha20Poly1305Factory, XChaCha20Poly1305Factory>();
        services.TryAddScoped<ICryptoProvider<Key>, XChaCha20Poly1305CryptoProvider>();
        services.TryAddScoped<IBlockProcessor<Key>, BlockProcessor<Key>>();

        services
            .TryAddScoped<Abstractions.Service.Decryption.XChaCha20Poly1305.IDecryptorBase,
                Service.Decryption.XChaCha20Poly1305.DecryptorBase>();
        services
            .TryAddScoped<Abstractions.Service.Decryption.XChaCha20Poly1305.IDecryptionService,
                Service.Decryption.XChaCha20Poly1305.DecryptionService>();

        return services;
    }
}