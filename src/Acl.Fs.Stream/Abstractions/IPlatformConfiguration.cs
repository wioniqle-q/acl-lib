namespace Acl.Fs.Stream.Abstractions;

internal interface IPlatformConfiguration
{
    void ConfigureStream(System.IO.Stream stream);
}