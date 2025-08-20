namespace Acl.Fs.Core.Abstractions;

internal interface IFileVersionValidator
{
    void ValidateVersion(byte majorVersion, byte minorVersion);
}