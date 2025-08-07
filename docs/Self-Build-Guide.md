# Self-Build Guide for Acl.Fs Library

This guide will help you build the Acl.Fs library from source code on your local machine.

## Getting Started

### 1. Clone the Repository

```bash
git clone <repository-url>
cd acl-lib
```

## Building the Project

### Option 1: Using the Build Script (Recommended)

The project includes automated build scripts that handle the entire build process.

#### Windows PowerShell

```powershell
# build (Release configuration)
.\Build.ps1
```

### Option 2: Manual Build Steps

If you prefer to build manually:

#### 1. Clean the Solution

```bash
dotnet clean Acl.Fs.sln
```

#### 2. Restore NuGet Packages

```bash
dotnet restore Acl.Fs.sln
```

#### 3. Build Source Projects

```bash
# Build all source projects
dotnet build src/Acl.Fs.Core/Acl.Fs.Core.csproj --configuration Release --no-restore
dotnet build src/Acl.Fs.Stream/Acl.Fs.Stream.csproj --configuration Release --no-restore
dotnet build src/Acl.Fs.Native/Acl.Fs.Native.csproj --configuration Release --no-restore
dotnet build src/Acl.Fs.Audit/Acl.Fs.Audit.csproj --configuration Release --no-restore
```

#### 4. Build Sample Projects

```bash
dotnet build samples/Acl.Fs.AesGcm.Sample/Acl.Fs.AesGcm.Sample.csproj --configuration Debug
dotnet build samples/Acl.Fs.ChaCha20Poly1305.Sample/Acl.Fs.ChaCha20Poly1305.Sample.csproj --configuration Debug
dotnet build samples/Acl.Fs.XChaCha20Poly1305.Sample/Acl.Fs.XChaCha20Poly1305.Sample.csproj --configuration Debug
dotnet build samples/Acl.Fs.Cli/Acl.Fs.Cli.csproj --configuration Debug
```

#### 5. Run Tests (Optional)

```bash
# Run unit tests
dotnet test tests/UnitTests/Acl.Fs.Core.UnitTests/Acl.Fs.Core.UnitTests.csproj
dotnet test tests/UnitTests/Acl.Fs.Stream.UnitTests/Acl.Fs.Stream.UnitTests.csproj
dotnet test tests/UnitTests/Acl.Fs.Native.UnitTests/Acl.Fs.Native.UnitTests.csproj
dotnet test tests/UnitTests/Acl.Fs.Audit.UnitTests/Acl.Fs.Audit.UnitTests.csproj

# Run integration tests
dotnet test tests/IntegrationTests/Acl.Fs.Core.IntegrationTests/Acl.Fs.Core.IntegrationTests.csproj
```

**Note**: This guide assumes you're building from the main branch. If you're building from a different branch or tag, some steps might vary slightly.
