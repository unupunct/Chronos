# Chronos build script
# Produces one portable self-contained Windows executable: publish\Chronos.exe
# Usage:  powershell -ExecutionPolicy Bypass -File build.ps1

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

Write-Host "=== Chronos - building portable exe ===" -ForegroundColor Cyan

dotnet publish Chronos.csproj `
    -c Release `
    -r win-x64 `
    --self-contained true `
    -p:PublishSingleFile=true `
    -p:IncludeNativeLibrariesForSelfExtract=true `
    -p:EnableCompressionInSingleFile=true `
    -p:PublishReadyToRun=true `
    -o "$root\publish"

if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed" }

# keep only the exe (pdb/xml not produced in Release; clean leftovers anyway)
Get-ChildItem "$root\publish" -Exclude 'Chronos.exe' | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue

$exe = Get-Item "$root\publish\Chronos.exe"
Write-Host ("Done: {0}  ({1:N1} MB)" -f $exe.FullName, ($exe.Length / 1MB)) -ForegroundColor Green
