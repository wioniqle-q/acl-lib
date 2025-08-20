using System.Runtime.CompilerServices;
using Acl.Fs.Core.Resource;
using Acl.Fs.Stream.Core;
using Microsoft.Extensions.Logging;
using static Acl.Fs.Constant.Storage.StorageConstants;

namespace Acl.Fs.Core.Utility;

internal static class CryptoPrimitives
{
    internal static System.IO.Stream CreateInputStream(string path, FileOptions fileOptions, ILogger logger)
    {
        ArgumentException.ThrowIfNullOrEmpty(path, ErrorMessages.SourcePathCannotBeNullOrInvalid);

        return DirectStreamFactory.Create(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            BufferSize,
            fileOptions,
            logger);
    }

    internal static System.IO.Stream CreateOutputStream(string path, FileOptions fileOptions, ILogger logger)
    {
        ArgumentException.ThrowIfNullOrEmpty(path, ErrorMessages.DestinationPathCannotBeNullOrInvalid);

        return DirectStreamFactory.Create(
            path,
            FileMode.Create,
            FileAccess.Write,
            FileShare.None,
            BufferSize,
            fileOptions,
            logger);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static int CalculateAlignedSize(int bytesRead, bool isLastBlock = true)
    {
        if (isLastBlock is not true) return bytesRead;
        return (bytesRead + SectorSize - 1) & ~(SectorSize - 1);
    }
}