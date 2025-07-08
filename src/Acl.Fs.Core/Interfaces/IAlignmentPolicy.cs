namespace Acl.Fs.Core.Interfaces;

internal interface IAlignmentPolicy
{
    int CalculateProcessingSize(int bytesRead, bool isLastBlock);
    int GetMetadataBufferSize();
    FileOptions GetFileOptions();
}