namespace Acl.Fs.Core.Abstractions;

internal interface IVersionValidationStrategy
{
    void Validate(byte minorVersion);
}