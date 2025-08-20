# Encryption Guide

This guide demonstrates how to use the encryption services provided by the library in a simple `Program.cs` example.

## Example Usage

Below is an example of how to use the XChaCha20Poly1305 encryption service:

```csharp
var builder = Host.CreateApplicationBuilder(args);

builder.Services.AddAclFsCore();
builder.Services.AddEncryptionComponents();
builder.Services.AddXChaCha20Poly1305Factory();
builder.Services.AddXChaCha20Poly1305EncryptionServices();
builder.Services.AddAuditLogger();

var encryptionService = builder.Services.BuildServiceProvider().GetRequiredService<IEncryptionService>();

var filePath = Path.Combine(@"C:\", "your_file.txt");
var destinationPath = Path.Combine(@"C:\", "your_file_encrypted.txt");

var password = new ReadOnlyMemory<byte>([ /* your password bytes */ ]);

var transferInstruction = new FileTransferInstruction(filePath, destinationPath);
var encryptionInput = new XChaCha20Poly1305EncryptionInput(password);

await encryptionService.EncryptFileAsync(transferInstruction, encryptionInput, CancellationToken.None);
```