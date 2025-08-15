# Changelog

All notable changes to this project will be documented in this file.

**Note:** This changelog is updated periodically and may not reflect the most recent changes immediately.

## [0.6.0-beta] - 2025-08-15

### Changed

- **API Breaking**: `IEncryptorBase` interfaces now use `ReadOnlyMemory<byte>` instead of `byte[]` for nonce parameters across all encryption algorithms (AES-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305)
- **Performance**: Removed unnecessary `ToArray()` calls in encryption services - nonce data is now passed directly from CryptoPool buffers without copying

## [0.5.0-beta] - 2025-08-15

### Changed

- **API Breaking**: Encryption and decryption service interfaces now use `ReadOnlyMemory<byte>` instead of `byte[]` for password parameters

### Security

- **Disposal**: Encryption/decryption input models now implement `IDisposable` with automatic memory clearing using `CryptographicOperations.ZeroMemory()` but user should use "using" statement to ensure proper disposal

### Technical

- **Input Models Refactored**: 
  - `AesEncryptionInput` and `AesDecryptionInput` converted to `readonly record struct` with `IDisposable` implementation
  - `ChaCha20Poly1305EncryptionInput`, `ChaCha20Poly1305DecryptionInput`, `XChaCha20Poly1305EncryptionInput`, and `XChaCha20Poly1305DecryptionInput` updated to use `ReadOnlyMemory<byte>`
- **Service Layer Updates**:
  - All `IEncryptorBase` and `IDecryptorBase` interfaces updated to accept `ReadOnlyMemory<byte> password` parameter
  - DecryptionService implementations cleaned up - removed redundant `finally` blocks with memory cleanup

## [0.4.0-beta] - 2025-08-15

### Changed

- Key preparation flow now uses `KeyPreparationService` (`PrepareKey(...)`, `PrepareKeyWithSalt(...)`) instead of constructing `KeyPreparationResult` directly

### Technical

- Renamed test file: `KeyPreparationResultTests.cs` → `KeyPreparationServiceTests.cs`
- Unit tests refactored to target the `KeyPreparationService` API, updating test names, setup, and assertions

## [0.3.0-beta] - 2025-08-09

### Added

- Platform-specific configuration 
- Lazy initialization for process-level system call optimizations
- Enhanced error messages with platform and implementation details (`UnsupportedPlatform`)

### Changed

- Refactored platform configuration logic into separate service classes
- Process-level syscalls (IO priority) now execute only once per application lifecycle instead of per file

### Technical

- Platform configurations now follow consistent architecture across Windows, macOS, and Linux
- Factory pattern implementation for runtime platform detection

## [0.2.1-beta] - 2025-08-08

### Added

- Cross-platform shell notification abstraction (`ShellNotifierFactory`)

### Changed

- The shell notification logic is now platform-specific and for now only available on Windows

## [0.2.0-beta] - 2025-08-02

### Added
- Dynamic salt size support based on environment (64 bytes for production, 32 bytes for CI/GitHub Actions)

### Changed
- Salt size is now dynamically determined by `SaltSize` constant instead of hardcoded 64 bytes
- Associated data buffer allocation now uses dynamic sizing: `SaltSize + sizeof(long) + sizeof(int)`
- All crypto provider tests updated to use dynamic salt sizing
- Binary data writing operations now use dynamic offsets based on actual salt size

### Security
- Implemented secure clearing of `associatedData` spans in all crypto providers

## [0.1.0-beta] - 2025-07-29

### Added
- Initial beta release
- Core filesystem constants and versioning
- AES-GCM encryption/decryption support
- ChaCha20-Poly1305 & XChaCha20-Poly1305 encryption/decryption support
- Argon2id key derivation
- Cross-platform native optimizations
- Stream-based encryption for large files
- Header alignment with sector size optimization
- Unit and integration tests (95% coverage)

### Changed

### Security

### Breaking Changes

### Notes
- This is a beta release - API may change before 1.0.0
- Production use not recommended until stable release
- Beta feedback and contributions help our project reach stable release faster
