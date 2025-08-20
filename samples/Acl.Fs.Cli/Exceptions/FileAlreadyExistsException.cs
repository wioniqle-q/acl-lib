namespace Acl.Fs.Cli.Exceptions;

internal sealed class FileAlreadyExistsException : Exception
{
    public string FilePath { get; }

    public FileAlreadyExistsException(string filePath) : base($"Destination file already exists: {filePath}")
    {
        FilePath = filePath;
    }

    public FileAlreadyExistsException(string filePath, string message) : base(message)
    {
        FilePath = filePath;
    }

    public FileAlreadyExistsException(string filePath, string message, Exception innerException) : base(message, innerException)
    {
        FilePath = filePath;
    }
}
