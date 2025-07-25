# Changelog

All notable changes to this project will be documented in this file.

**Note:** This changelog is updated periodically and may not reflect the most recent changes immediately.

## [0.3.0-beta] - 2025-07-26

### Fixed
- **XChaCha20Poly1305 Nonce Size Handling** - planned fix for proper 24-byte nonce support
  - Fixed `CryptoOperations.DeriveNonce` to accept nonce size parameter
  - Fixed `MetadataService.PrepareMetadata` to handle variable nonce sizes
  - Fixed `HeaderReader.ReadHeaderAsync` to support XChaCha20Poly1305 24-byte nonces
  - Fixed `BlockCalculator.CalculateTotalBlocks` to use actual metadata buffer sizes

### Enhanced
- **BufferManager** - Added `NonceSize` property to both encryption and decryption buffer managers
- **BlockProcessor** - Updated to use dynamic nonce sizes from BufferManager
- **Version Constants** - Added XChaCha20Poly1305-specific header size calculations

### Breaking Changes
- **v0.2.x files incompatible** - XChaCha20Poly1305 files encrypted with v0.2.x cannot be decrypted with v0.3.x due to nonce size fix
- **IBufferManager interface** - Added `NonceSize` property (affects custom implementations)
- **IBlockProcessor interface** - Updated `ProcessBlockAsync` signature to include `nonceSize` parameter for decryption
- **IMetadataService interface** - Added overload for `PrepareMetadata` with `nonceSize` parameter  
- **IHeaderReader interface** - Added overload for `ReadHeaderAsync` with `nonceSize` parameter

### Technical Details

## [0.2.0-beta] - 2025-07-23

### Added
- **XChaCha20Poly1305 Encryption/Decryption Support** 
  - 24-byte nonces (vs 12-byte for ChaCha20Poly1305)
- **XChaCha20Poly1305 Service Extensions** - Dependency injection registration
  - `AddXChaCha20Poly1305Factory()` extension method
  - `AddXChaCha20Poly1305EncryptionServices()` extension method  
  - `AddXChaCha20Poly1305DecryptionServices()` extension method

### Enhanced
- **BufferManager** - Updated to support multiple nonce sizes
  - Constructor now accepts `nonceSize` parameter for algorithm-specific buffer allocation
- **Crypto Constants** - Added `XChaCha20Poly1305NonceSize = 24` constant

### Fixed

### Technical Details
- 24-byte nonces providing better resistance to nonce collision

### Breaking Changes
- BufferManager constructor signature updated to include `nonceSize` parameter
- Existing BufferManager instantiations need to specify appropriate nonce size

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