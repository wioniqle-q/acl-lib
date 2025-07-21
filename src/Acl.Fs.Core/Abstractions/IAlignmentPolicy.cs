namespace Acl.Fs.Core.Abstractions;

internal interface IAlignmentPolicy
{
    int CalculateProcessingSize(int bytesRead, bool isLastBlock);
    int GetMetadataBufferSize();
    FileOptions GetFileOptions();
}