using Acl.Fs.Cli.Abstractions.Services;
using Acl.Fs.Cli.Configuration;
using Acl.Fs.Cli.Exceptions;
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

    public void CleanupFailedOperation(string destinationPath, string? protectedRootPath = null)
    {
        try
        {
            if (TryDeleteFile(destinationPath))
                _logger.LogWarning("Deleted partially created file: {DestinationPath}", destinationPath);

            var directory = Path.GetDirectoryName(destinationPath);
            while (string.IsNullOrEmpty(directory) is not true)
            {
                if (Directory.Exists(directory) is not true)
                {
                    _logger.LogDebug("Directory no longer exists, stopping cleanup: {DirectoryPath}", directory);
                    break;
                }

                if (string.IsNullOrEmpty(protectedRootPath) is not true &&
                    Path.GetFullPath(directory).Equals(Path.GetFullPath(protectedRootPath),
                        StringComparison.OrdinalIgnoreCase))
                {
                    _logger.LogDebug("Stopped cleanup at protected root path: {ProtectedPath}", protectedRootPath);
                    break;
                }

                try
                {
                    if (TryIsDirectoryEmpty(directory))
                    {
                        if (TryDeleteDirectory(directory))
                        {
                            _logger.LogWarning("Deleted empty directory: {DirectoryPath}", directory);
                            directory = Path.GetDirectoryName(directory);
                        }
                        else
                        {
                            _logger.LogWarning("Could not delete directory: {DirectoryPath}", directory);
                            break;
                        }
                    }
                    else
                    {
                        _logger.LogDebug("Directory is not empty, stopping cleanup: {DirectoryPath}", directory);
                        break;
                    }
                }
                catch (Exception dirEx) when (dirEx is DirectoryNotFoundException or FileNotFoundException)
                {
                    _logger.LogDebug("Directory was already deleted by external process: {DirectoryPath}", directory);
                    directory = Path.GetDirectoryName(directory);
                }
                catch (Exception dirEx)
                {
                    _logger.LogWarning(dirEx, "Could not process directory: {DirectoryPath}", directory);
                    break;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to cleanup after operation failure for: {DestinationPath}", destinationPath);
        }
    }

    private void ValidateDestinationFile(string destinationPath, CryptoSettings settings)
    {
        if (File.Exists(destinationPath) is not true) return;
        if (settings.OverwriteExisting is not true)
            throw new FileAlreadyExistsException(destinationPath);

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

    private bool TryDeleteFile(string filePath)
    {
        try
        {
            if (File.Exists(filePath) is not true)
            {
                _logger.LogDebug("File no longer exists: {FilePath}", filePath);
                return false;
            }

            File.Delete(filePath);
            return true;
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            _logger.LogDebug("File was already deleted by external process: {FilePath}", filePath);
            return false;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger.LogDebug("Failed to delete file: {FilePath}. Error: {Error}", filePath, ex.Message);
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Unexpected error deleting file: {FilePath}", filePath);
            return false;
        }
    }

    private bool TryIsDirectoryEmpty(string directoryPath)
    {
        try
        {
            if (Directory.Exists(directoryPath) is not true) return false;

            return Directory.EnumerateFileSystemEntries(directoryPath).Any() is not true;
        }
        catch (Exception ex) when (ex is DirectoryNotFoundException or FileNotFoundException)
        {
            _logger.LogDebug("Directory was deleted by external process: {DirectoryPath}", directoryPath);
            return false;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger.LogDebug("Failed to check directory contents: {DirectoryPath}. Error: {Error}", directoryPath,
                ex.Message);
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Unexpected error checking directory: {DirectoryPath}", directoryPath);
            return false;
        }
    }

    private bool TryDeleteDirectory(string directoryPath)
    {
        try
        {
            if (Directory.Exists(directoryPath) is not true)
            {
                _logger.LogDebug("Directory no longer exists: {DirectoryPath}", directoryPath);
                return false;
            }

            Directory.Delete(directoryPath);
            return true;
        }
        catch (Exception ex) when (ex is DirectoryNotFoundException or FileNotFoundException)
        {
            _logger.LogDebug("Directory was already deleted by external process: {DirectoryPath}", directoryPath);
            return false;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger.LogDebug("Failed to delete directory: {DirectoryPath}. Error: {Error}", directoryPath, ex.Message);
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Unexpected error deleting directory: {DirectoryPath}", directoryPath);
            return false;
        }
    }
}