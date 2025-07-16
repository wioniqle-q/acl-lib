using System.Runtime.CompilerServices;

namespace Acl.Fs.Core.Policy;

internal static class SectorFileOptions
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static FileOptions GetFileOptions(bool sectorAligned)
    {
        var options = FileOptions.Asynchronous | FileOptions.SequentialScan | FileOptions.WriteThrough;

        if (sectorAligned)
            options |= (FileOptions)0x20000000;

        return options;
    }
}