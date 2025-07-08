namespace Acl.Fs.Core.Services.Policies;

internal static class SectorFileOptions
{
    internal static FileOptions GetFileOptions(bool sectorAligned)
    {
        var options = FileOptions.Asynchronous | FileOptions.SequentialScan | FileOptions.WriteThrough;

        if (sectorAligned)
            options |= (FileOptions)0x20000000;

        return options;
    }
}