# Decryption Guide

This guide demonstrates how to use the decryption services provided by the library in a simple `Program.cs` example.

## Example Usage

Below is an example of how to use the XChaCha20Poly1305 decryption service:

```csharp
var builder = Host.CreateApplicationBuilder(args);

builder.Services.AddAclFsCore();
builder.Services.AddDecryptionComponents();
builder.Services.AddXChaCha20Poly1305Factory();
builder.Services.AddXChaCha20Poly1305DecryptionServices();
builder.Services.AddAuditLogger();

var decryptionService = builder.Services.BuildServiceProvider().GetRequiredService<IDecryptionService>();

var filePath = Path.Combine(@"C:\", "your_file.txt");
var destinationPath = Path.Combine(@"C:\", "your_file_decrypted.txt");

var password = new ReadOnlyMemory<byte>([ /* your password bytes */ ]);

var transferInstruction = new FileTransferInstruction(filePath, destinationPath);
var decryptionInput = new XChaCha20Poly1305DecryptionInput(password);

await decryptionService.DecryptFileAsync(transferInstruction, decryptionInput, CancellationToken.None);
```