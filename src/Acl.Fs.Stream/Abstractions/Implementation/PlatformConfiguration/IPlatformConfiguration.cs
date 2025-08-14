namespace Acl.Fs.Stream.Abstractions.Implementation.PlatformConfiguration;

internal interface IPlatformConfiguration
{
    void ConfigureStream(System.IO.Stream stream);
}