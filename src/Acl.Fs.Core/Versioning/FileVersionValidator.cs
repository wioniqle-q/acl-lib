using System.Collections.Frozen;
using Acl.Fs.Constant.Versioning;
using Acl.Fs.Core.Abstractions;
using Acl.Fs.Core.Resource;
using Acl.Fs.Core.Versioning.Exceptions;
using Acl.Fs.Core.Versioning.ValidationStrategies;
using Microsoft.Extensions.Logging;

namespace Acl.Fs.Core.Versioning;

internal sealed class FileVersionValidator(ILogger<FileVersionValidator> logger) : IFileVersionValidator
{
    private static readonly FrozenDictionary<byte, IVersionValidationStrategy> Strategies =
        new Dictionary<byte, IVersionValidationStrategy>
        {
            { 0, new V0ValidationStrategy() }
        }.ToFrozenDictionary();

    private readonly ILogger<FileVersionValidator>
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

    public void ValidateVersion(byte majorVersion, byte minorVersion)
    {
        try
        {
            ValidateBasicRules(majorVersion, minorVersion);

            if (Strategies.TryGetValue(majorVersion, out var strategy) is not true)
                throw new VersionValidationException(
                    string.Format(ErrorMessages.UnsupportedMajorVersion, majorVersion, minorVersion));

            strategy.Validate(minorVersion);
        }
        catch (VersionValidationException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, ErrorMessages.VersionValidationFailed);
            throw new VersionValidationException(ErrorMessages.VersionValidationFailed, ex);
        }
    }

    private static void ValidateBasicRules(byte majorVersion, byte minorVersion)
    {
        switch (majorVersion)
        {
            case 0 when minorVersion is 0:
                throw new VersionValidationException(ErrorMessages.InvalidVersionZeroZero);
            case > VersionConstants.CurrentMajorVersion:
                throw new VersionValidationException(
                    string.Format(ErrorMessages.FutureMajorVersionNotSupported,
                        majorVersion, minorVersion, VersionConstants.CurrentMajorVersion));
        }

        if (minorVersion > VersionConstants.CurrentMinorVersion)
            throw new VersionValidationException(
                string.Format(ErrorMessages.FutureMinorVersionNotSupported,
                    majorVersion, minorVersion, VersionConstants.CurrentMinorVersion));
    }
}