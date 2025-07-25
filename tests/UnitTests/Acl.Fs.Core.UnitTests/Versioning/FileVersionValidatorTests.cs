using Acl.Fs.Core.Resource;
using Acl.Fs.Core.Versioning;
using Acl.Fs.Core.Versioning.Exceptions;
using Microsoft.Extensions.Logging;
using Moq;
using static Acl.Fs.Constant.Versioning.VersionConstants;

namespace Acl.Fs.Core.UnitTests.Versioning;

public sealed class FileVersionValidatorTests
{
    private readonly FileVersionValidator _validator;

    public FileVersionValidatorTests()
    {
        var mockLogger = new Mock<ILogger<FileVersionValidator>>();
        _validator = new FileVersionValidator(mockLogger.Object);
    }

    [Fact]
    public void Constructor_WhenLoggerIsNull_ShouldThrowArgumentNullException()
    {
        var exception = Assert.Throws<ArgumentNullException>(() => new FileVersionValidator(null!));
        Assert.Equal("logger", exception.ParamName);
    }

    [Fact]
    public void ValidateVersion_WhenCurrentSupportedVersions_ShouldNotThrow()
    {
        for (byte minorVersion = 1; minorVersion <= CurrentMinorVersion; minorVersion++)
        {
            var currentMinorVersion = minorVersion;
            var exception =
                Record.Exception(() => _validator.ValidateVersion(CurrentMajorVersion, currentMinorVersion));
            Assert.Null(exception);
        }
    }

    [Fact]
    public void ValidateVersion_WhenVersionIsZeroZero_ShouldThrowVersionValidationException()
    {
        var exception = Assert.Throws<VersionValidationException>(() =>
            _validator.ValidateVersion(0, 0));

        Assert.Equal(ErrorMessages.InvalidVersionZeroZero, exception.Message);
    }

    [Fact]
    public void ValidateVersion_WhenFutureMajorVersion_ShouldThrowVersionValidationException()
    {
        const byte futureMajorVersion = CurrentMajorVersion + 1;

        var exception = Assert.Throws<VersionValidationException>(() =>
            _validator.ValidateVersion(futureMajorVersion, 0));

        var expectedMessage = string.Format(ErrorMessages.FutureMajorVersionNotSupported,
            futureMajorVersion, 0, CurrentMajorVersion);
        Assert.Equal(expectedMessage, exception.Message);
    }

    [Fact]
    public void ValidateVersion_WhenFutureMinorVersionForCurrentMajor_ShouldThrowVersionValidationException()
    {
        const byte futureMinorVersion = CurrentMinorVersion + 1;

        var exception = Assert.Throws<VersionValidationException>(() =>
            _validator.ValidateVersion(CurrentMajorVersion, futureMinorVersion));

        var expectedMessage = string.Format(ErrorMessages.FutureMinorVersionNotSupported,
            CurrentMajorVersion, futureMinorVersion, CurrentMinorVersion);
        Assert.Equal(expectedMessage, exception.Message);
    }

    [Fact]
    public void ValidateVersion_WhenFutureMajorVersionWithAnyMinor_ShouldThrowVersionValidationException()
    {
        var futureMajorVersions = new byte[] { CurrentMajorVersion + 1, CurrentMajorVersion + 2, 255 };

        foreach (var majorVersion in futureMajorVersions)
        {
            var exception = Assert.Throws<VersionValidationException>(() =>
                _validator.ValidateVersion(majorVersion, 0));

            var expectedMessage = string.Format(ErrorMessages.FutureMajorVersionNotSupported,
                majorVersion, 0, CurrentMajorVersion);
            Assert.Equal(expectedMessage, exception.Message);
        }
    }

    [Fact]
    public void ValidateVersion_WhenValidVersions_ShouldCompleteSuccessfully()
    {
        for (byte minorVersion = 1; minorVersion <= CurrentMinorVersion; minorVersion++)
        {
            var currentMinorVersion = minorVersion;
            var exception =
                Record.Exception(() => _validator.ValidateVersion(CurrentMajorVersion, currentMinorVersion));
            Assert.Null(exception);
        }
    }

    [Fact]
    public void ValidateVersion_WhenInvalidVersions_ShouldThrowVersionValidationException()
    {
        var invalidVersions = new[]
        {
            (major: (byte)0, minor: (byte)0), // v0.0 always invalid
            (major: CurrentMajorVersion, minor: (byte)(CurrentMinorVersion + 1)), // Future minor
            (major: (byte)(CurrentMajorVersion + 1), minor: (byte)0), // Future major
            (major: (byte)255, minor: (byte)255) // Way future version
        };

        foreach (var (major, minor) in invalidVersions)
        {
            var exception = Assert.Throws<VersionValidationException>(() =>
                _validator.ValidateVersion(major, minor));

            Assert.NotNull(exception);
            Assert.IsType<VersionValidationException>(exception);
        }
    }

    [Fact]
    public void ValidateVersion_BoundaryConditions_ShouldWorkCorrectly()
    {
        var exception = Record.Exception(() =>
            _validator.ValidateVersion(CurrentMajorVersion, CurrentMinorVersion));
        Assert.Null(exception);

        var futureException = Assert.Throws<VersionValidationException>(() =>
            _validator.ValidateVersion(CurrentMajorVersion, CurrentMinorVersion + 1));
        Assert.NotNull(futureException);
    }
}