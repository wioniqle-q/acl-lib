#!/usr/bin/env pwsh

param(
    [string]$Configuration = "Release",
    [string]$Runtime = $null
)

$ROOT = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $ROOT

$ArtifactsCliPath = Join-Path $ROOT "artifacts"
$ArtifactsCliPath = Join-Path $ArtifactsCliPath "Cli"
if (Test-Path $ArtifactsCliPath) {
    Write-Host "Cleaning previous build artifacts..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force $ArtifactsCliPath -ErrorAction SilentlyContinue
    Write-Host "Previous artifacts cleaned" -ForegroundColor Green
}

if (-not $Runtime) {
    if ($IsWindows -or ($env:OS -eq "Windows_NT")) {
        $Runtime = "win-x64"
    } elseif ($IsLinux -or ($PSVersionTable.Platform -eq "Unix" -and (uname) -eq "Linux")) {
        $Runtime = "linux-x64"
    } elseif ($IsMacOS -or ($PSVersionTable.Platform -eq "Unix" -and (uname) -eq "Darwin")) {
        $Runtime = "osx-x64"
    } else {
        Write-Error "Unable to determine runtime. Please specify -Runtime parameter (win-x64, linux-x64, osx-x64)."
        exit 1
    }
}

Write-Host "Building for runtime: $Runtime" -ForegroundColor Green

dotnet restore
dotnet build -c $Configuration

$CliPath = Join-Path $ROOT "samples"
$CliPath = Join-Path $CliPath "Acl.Fs.Cli"
Set-Location $CliPath
dotnet restore
dotnet build -c $Configuration

dotnet publish -c $Configuration -r $Runtime --self-contained true

$PublishPath = Join-Path $CliPath "bin"
$PublishPath = Join-Path $PublishPath $Configuration
$PublishPath = Join-Path $PublishPath "net*"
$PublishPath = Join-Path $PublishPath $Runtime
$PublishPath = Join-Path $PublishPath "publish"

$PublishDirs = Get-ChildItem -Path $PublishPath -Directory -ErrorAction SilentlyContinue
if($PublishDirs.Count -eq 0) {
    Write-Error "No publish directories found in $PublishPath."
    exit 1
}
$ActualPublishPath = $PublishDirs[0].FullName

$TargetPath = Join-Path $ROOT "artifacts"
$TargetPath = Join-Path $TargetPath "Cli"
Remove-Item -Recurse -Force $TargetPath -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $TargetPath -Force | Out-Null

Copy-Item (Join-Path $ActualPublishPath "*") $TargetPath -Recurse
Remove-Item -Recurse -Force $ActualPublishPath

Write-Host "Build completed for $Runtime" -ForegroundColor Green
Write-Host "Files copied to: $TargetPath" -ForegroundColor Yellow
