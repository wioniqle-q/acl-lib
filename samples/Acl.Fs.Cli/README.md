# Acl.Fs.Cli - XChaCha20Poly1305 File Encryption/Decryption CLI

## Usage

### Global Options

- `--encrypted-folder, -e <path>`: Path to the folder containing encrypted files
- `--decrypted-folder, -d <path>`: Path to the folder containing decrypted files
- `--password, -p <password>`: Password for encryption/decryption operations

### Commands

#### Encrypt Files

**Short form:**

```bash
dotnet run -- encrypt -e "C:\MyFiles" -d "C:\SecureFiles" -p "Password"
```

#### Decrypt Files

Decrypts all files from the encrypted folder to the decrypted folder:

```bash
dotnet run -- decrypt --encrypted-folder "C:\SecureFiles" --decrypted-folder "C:\MyFiles" --password "Password"
```

**Short form:**

```bash
dotnet run -- decrypt -e "C:\SecureFiles" -d "C:\MyFiles" -p "Password"
```

### Examples

#### Basic Encryption

```bash
# Encrypt all files in Documents folder
dotnet run -- encrypt -e "C:\Users\xxx\Documents" -d "C:\Users\xxx\SecureDocuments" -p "Password"
```

#### Basic Decryption

```bash
# Decrypt all files back to Documents folder
dotnet run -- decrypt -e "C:\Users\xxx\SecureDocuments" -d "C:\Users\xxx\Documents" -p "Password"
```

## Configuration

### appsettings.json

You can customize the behavior by modifying `appsettings.json`:

```json
{
  "CryptoSettings": {
    "DefaultEncryptedPrefix": "acl_",
    "MaxConcurrency": 2,
    "OverwriteExisting": false
  }
}
```

**Configuration Options:**

- `DefaultEncryptedPrefix`: Prefix added to encrypted files (default: "acl_")
- `MaxConcurrency`: Maximum number of concurrent file operations (default: 2)
- `OverwriteExisting`: Whether to overwrite existing files during encryption/decryption (default: false)

## Development

### Publishing as Single File

```bash
dotnet publish -c Release -r win-x64 --self-contained true
```

## Security Considerations

1. **Password Storage**: Never store passwords in scripts or configuration files
2. **Secure Channels**: Use secure channels when transmitting encrypted files
3. **Key Management**: Implement proper key management practices
4. **Backup Strategy**: Maintain secure backups of encryption keys/passwords
5. **Regular Updates**: Keep the CLI and its dependencies updated

---

**⚠️ Important Security Note**: Always test the encryption/decryption process with non-critical files first. Ensure you
have secure backups of your encryption passwords. Lost passwords cannot be recovered and will result in permanent data
loss. Also this repo under development. For now there's no any release.
