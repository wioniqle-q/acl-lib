# Self-Build Guide for Acl.Fs Library

This guide will help you build the Acl.Fs library from source code on your local machine.

## Prerequisites

### System Requirements
- .NET 9.0 SDK 
- Git (for cloning the repository as you wish)

### Platform-Specific Requirements

#### Linux
- PowerShell (for running build scripts)
- Package manager (dnf, apt, etc.)

#### Windows
- PowerShell

## Getting Started

### 1. Clone the Repository

```bash
git clone <repository-url>
cd acl-lib
```

## Building the Project

## Linux Build Instructions

### Step 1: Install PowerShell (if not already installed)

#### For RedHat/AlmaLinux/Rocky Linux/CentOS:
```bash
# Download PowerShell RPM package from GitHub releases
# Copy Download Link: rh.x86_64.rpm

# Install PowerShell
sudo dnf install <copied-rpm-link>
```

### Step 2: Build Using PowerShell Script (Recommended)

```bash
# Navigate to project directory
cd acl-lib

# Build the core libraries (If you want to develop the library)
pwsh -File Build.ps1 

# Build the CLI application (If you want to develop or just use the CLI)
pwsh -File CliBuild.ps1
```

### Step 3: Run the CLI Application

After successful build, the CLI binaries will be available in `artifacts/Cli` directory:

```bash
# Navigate to the CLI directory
cd artifacts/Cli

# Run the CLI application
./Acl.Fs.Cli --help

# Or run with dotnet
dotnet Acl.Fs.Cli.dll --help
```

### Alternative: Manual Build Steps (Linux)

If you prefer to build manually without PowerShell:

```bash
# 1. Restore NuGet packages
dotnet restore Acl.Fs.sln

# 2. Build the solution
dotnet build Acl.Fs.sln --configuration Release

# 3. Publish for Linux
dotnet publish src/Acl.Fs.Core/Acl.Fs.Core.csproj --configuration Release --runtime linux-x64 --output artifacts/linux-x64
dotnet publish samples/Acl.Fs.Cli/Acl.Fs.Cli.csproj --configuration Release --runtime linux-x64 --output artifacts/linux-x64
```

## Windows Build Instructions

### Step 1: Build Using PowerShell Script (Recommended)

```powershell
# Navigate to project directory
cd acl-lib

# Build the core libraries (If you want to develop the library)
.\Build.ps1

# Build the CLI application (If you want to develop or just use the CLI)
.\CliBuild-run.bat
```

### Step 2: Run the CLI Application

After successful build, the CLI binaries will be available in `artifacts/Cli` directory:

```powershell
# Navigate to the CLI directory
cd artifacts/Cli

# Run the CLI application
.\Acl.Fs.Cli.exe --help
```

### Alternative: Manual Build Steps (Windows)

```powershell
# 1. Restore NuGet packages
dotnet restore Acl.Fs.sln

# 2. Build the solution
dotnet build Acl.Fs.sln --configuration Release

# 3. Publish for Windows
dotnet publish src/Acl.Fs.Core/Acl.Fs.Core.csproj --configuration Release --runtime win-x64 --output artifacts/win-x64
dotnet publish samples/Acl.Fs.Cli/Acl.Fs.Cli.csproj --configuration Release --runtime win-x64 --output artifacts/win-x64
```

#### .NET SDK Not Found
- Install .NET 9.0 SDK from: https://dotnet.microsoft.com/download

## Next Steps

After successfully building the library:

1. **For Contributing**: See [CONTRIBUTING.md](CONTRIBUTING.md)

## Support

If you encounter any issues during the build process:

1. Check the [Issue Guidelines](Issue-Guidelines.md)
2. Review existing issues in the GitHub repository
3. Create a new issue with detailed information about your build environment and error messages