# Builds the module from Source/ into Dist/ with ModuleBuilder, clearing the previous build
# first. tests.ps1 and coverage.ps1 import the BUILT module, so this has to run before them.
#
# Usage (from the repo root):
#   ./tasks.ps1 build
#   pwsh -File Tools/build.ps1

$ErrorActionPreference = 'Stop'

. $(Join-Path $PSScriptRoot 'module_info.ps1')
$info = Get-ModuleInfo

Write-Host "--------------------------------"
Write-Host "Cleaning $($info.DistRoot)..."
Write-Host "--------------------------------"
# Guarded: on a fresh clone there is no Dist/ yet, and an unguarded Remove-Item would fail
# the very first build.
if (Test-Path -LiteralPath $info.DistRoot) {
  Remove-Item -LiteralPath $info.DistRoot -Recurse -Force
}
Write-Host "Dist directory cleaned successfully"

Write-Host "--------------------------------"
Write-Host "Building $($info.ModuleName) $($info.SemVer)..."
Write-Host "--------------------------------"
# Build-Module finds build.psd1 relative to the working directory, so pin it to the repo
# root instead of relying on where the caller happened to be.
Push-Location $info.RepoRoot
try {
  Import-Module ModuleBuilder
  Build-Module
  Write-Host "Module built successfully"
} catch {
  throw "Building module failed. ($($_.Exception.Message))"
} finally {
  Pop-Location
}
