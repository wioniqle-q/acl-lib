# Acl.Fs.Cli

A simple sample command-line tool for encrypting and decrypting files using XChaCha20Poly1305 encryption.

> [!CAUTION]
> acl-lib and Acl.Fs.Cli is currently in BETA and is intended as a SAMPLE/DEMONSTRATION only.
> In Beta Version, features may be unstable or incomplete.
> Use at your own risk. No guarantees or warranties provided.
> Always backup your important files before using this tool.
> Always test the encryption/decryption process with non-critical files first.
> Ensure you have secure backups of your encryption passwords.
> Lost passwords cannot be recovered and will result in permanent data loss.

> [!TIP]
> Use strong, unique passwords.
> Never store passwords in scripts or configuration files.
> Use secure channels when transmitting encrypted files.

## Installation

1. Clone or download the repository
2. Navigate the terminal to the root folder `acl-lib`
3. Run the script: `CliBuild-run.bat`
4. Find the compiled CLI tool in: `artifacts\Cli` folder

That's it! You can now use the CLI.

## Usage

### Commands

- `encrypt` - Encrypt files from source folder to destination folder
- `decrypt` - Decrypt files from source folder to destination folder

### Options

| Option          | Short | Description                          |
|-----------------|-------|--------------------------------------|
| `--source`      | `-s`  | Path to the source files folder      |
| `--destination` | `-d`  | Path to the destination files folder |
| `--password`    | `-pw` | Password for encryption/decryption   |

## Quick Start

### Encrypt Files

```bash
encrypt --source "C:\MyDocuments" --destination "C:\EncryptedDocuments" --password "your-secure-password"
```

### Decrypt Files

```bash
decrypt --source "C:\EncryptedDocuments" --destination "C:\DecryptedDocuments" --password "your-secure-password"
```

## Requirements

- .NET 9.0.7 SDK
- Windows, macOS, or Linux

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.