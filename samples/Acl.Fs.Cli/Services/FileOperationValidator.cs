using Acl.Fs.Cli.Abstractions.Services;
using Acl.Fs.Cli.Configuration;
using Microsoft.Extensions.Logging;

namespace Acl.Fs.Cli.Services;

internal sealed class FileOperationValidator(ILogger<FileOperationValidator> logger) : IFileOperationValidator
{
    private readonly ILogger<FileOperationValidator>
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

    public void ValidateFileOperation(string sourceFilePath, string destinationPath, CryptoSettings settings,
        bool isEncryption = false)
    {
        ValidateDestinationFile(destinationPath, settings);
        ValidateDiskSpace(sourceFilePath, destinationPath, isEncryption);
    }

    private void ValidateDestinationFile(string destinationPath, CryptoSettings settings)
    {
        if (File.Exists(destinationPath) is not true) return;
        if (settings.OverwriteExisting is not true)
            throw new InvalidOperationException($"Destination file already exists: {destinationPath}");

        _logger.LogWarning("Overwriting existing file: {DestinationPath}", destinationPath);
    }

    private static void ValidateDiskSpace(string sourceFilePath, string destinationPath, bool isEncryption = false)
    {
        var sourceFileInfo = new FileInfo(sourceFilePath);
        var destinationDrive = new DriveInfo(Path.GetPathRoot(destinationPath)!);

        var requiredSpace = isEncryption ? sourceFileInfo.Length * 2 : sourceFileInfo.Length;

        if (destinationDrive.AvailableFreeSpace < requiredSpace)
            throw new InvalidOperationException(
                $"Insufficient disk space on {destinationDrive.Name}. Required: {requiredSpace:N0} bytes, Available: {destinationDrive.AvailableFreeSpace:N0} bytes");
    }

    public void CleanupFailedOperation(string destinationPath, string? protectedRootPath = null)
    {
        try
        {
            if (File.Exists(destinationPath))
            {
                File.Delete(destinationPath);
                _logger.LogWarning("Deleted partially created file: {DestinationPath}", destinationPath);
            }

            var directory = Path.GetDirectoryName(destinationPath);
            while (string.IsNullOrEmpty(directory) is not true && Directory.Exists(directory))
            {
                if (string.IsNullOrEmpty(protectedRootPath) is not true &&
                    Path.GetFullPath(directory).Equals(Path.GetFullPath(protectedRootPath),
                        StringComparison.OrdinalIgnoreCase))
                {
                    _logger.LogDebug("Stopped cleanup at protected root path: {ProtectedPath}", protectedRootPath);
                    break;
                }

                try
                {
                    if (Directory.EnumerateFileSystemEntries(directory).Any() is not true)
                    {
                        Directory.Delete(directory);
                        _logger.LogWarning("Deleted empty directory: {DirectoryPath}", directory);

                        directory = Path.GetDirectoryName(directory);
                    }
                    else
                    {
                        break;
                    }
                }
                catch (Exception dirEx)
                {
                    _logger.LogWarning(dirEx, "Could not delete directory: {DirectoryPath}", directory);
                    break;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to cleanup after operation failure for: {DestinationPath}", destinationPath);
        }
    }
}