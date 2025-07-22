# Changelog

All notable changes to this project will be documented in this file.

**Note:** This changelog is updated periodically and may not reflect the most recent changes immediately.

## [0.1.1-beta] - 2025-07-22

### Fixed
- Fixed version validation issue where v0.1 beta versions were incorrectly rejected
- Added V0ValidationStrategy to support major version 0 (beta versions)
- Corrected ValidateBasicRules logic to properly handle v0.0 rejection while allowing valid major versions with minor version 0
- Improved FileVersionValidator to include validation strategy for major version 0

### Added
- Unit tests for FileVersionValidator
- Unit tests for V0ValidationStrategy

### Technical Details
- FileVersionValidator now includes { 0, new V0ValidationStrategy() } in strategies dictionary
- V0ValidationStrategy validates minor versions for beta v0.x releases
- ValidateBasicRules now only rejects v0.0 specifically, not all versions with minor version 0

## [0.1.0-beta] - 2025-07-22

### Added
- Initial beta release
- Core filesystem constants and versioning
- AES-GCM encryption/decryption support
- ChaCha20-Poly1305 encryption/decryption support
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