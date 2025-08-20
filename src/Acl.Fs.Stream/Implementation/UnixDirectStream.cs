using System.Runtime.InteropServices;
using Acl.Fs.Native.Platform.Unix;
using Acl.Fs.Stream.Abstractions;
using Acl.Fs.Stream.Resource;
using Microsoft.Extensions.Logging;

namespace Acl.Fs.Stream.Implementation;

internal sealed class UnixDirectStream(
    string path,
    FileMode mode,
    FileAccess access,
    FileShare share,
    int bufferSize,
    FileOptions options,
    ILogger logger)
    : DirectStreamBase<FileStream>(
        new FileStream(path ?? throw new ArgumentNullException(nameof(path)), mode, access, share, bufferSize, options),
        logger)
{
    protected override void ExecutePlatformSpecificFlush(CancellationToken cancellationToken)
    {
        if (UnixKernel.Fsync(InnerStream.SafeFileHandle) is not 0)
            throw new IOException(string.Format(ErrorMessages.UnixFsyncFailed, Marshal.GetLastWin32Error()));
    }
}