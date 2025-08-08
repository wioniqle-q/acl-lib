# Changelog

All notable changes to this project will be documented in this file.

**Note:** This changelog is updated periodically and may not reflect the most recent changes immediately.

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