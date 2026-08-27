# Single source of truth for "which module does this repo build, and where does it land?".
# Every other tool asks this instead of hardcoding a name that Tools/prepare.ps1 has already
# changed. build.psd1 is the authority, since ModuleBuilder reads the same file.
#
# Usage:
#   . $(Join-Path $PSScriptRoot 'module_info.ps1')
#   $info = Get-ModuleInfo

function Get-ModuleInfo {
  [OutputType([hashtable])]
  param(
    # Repo root. Defaults to the parent of Tools/, which is where this script lives, so
    # callers in Tests/ or .github/ get the right answer without passing anything.
    [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot)
  )

  $buildConfigPath = Join-Path $RepoRoot 'build.psd1'
  if (-not (Test-Path -LiteralPath $buildConfigPath)) {
    throw "build.psd1 not found at '$buildConfigPath'."
  }
  $buildConfig = Import-PowerShellDataFile -LiteralPath $buildConfigPath

  foreach ($key in 'ModuleManifest', 'OutputDirectory', 'SemVer') {
    if (-not $buildConfig.$key) { throw "build.psd1 has no '$key' entry." }
  }

  # build.psd1 ships Windows-style separators (ModuleBuilder's own convention). Normalise
  # them so the paths also resolve under pwsh on Linux and macOS.
  $sep = [IO.Path]::DirectorySeparatorChar
  $sourceManifest = Join-Path $RepoRoot ($buildConfig.ModuleManifest -replace '\\', $sep)
  $sourceRoot = Split-Path -Parent $sourceManifest

  # OutputDirectory is relative to the MANIFEST, not to the repo root. GetFullPath only
  # collapses the '..' segments here; the input is already absolute.
  $distRoot = [IO.Path]::GetFullPath((Join-Path $sourceRoot ($buildConfig.OutputDirectory -replace '\\', $sep)))

  @{
    RepoRoot       = $RepoRoot
    ModuleName     = [IO.Path]::GetFileNameWithoutExtension($sourceManifest)
    SourceManifest = $sourceManifest
    SourceRoot     = $sourceRoot
    DistRoot       = $distRoot
    SemVer         = $buildConfig.SemVer
  }
}

function Get-BuiltManifestPath {
  <#
    .SYNOPSIS
    Path to the most recently built manifest under Dist/, or a throw explaining how to make one.
  #>
  [OutputType([string])]
  param(
    [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot)
  )

  $info = Get-ModuleInfo -RepoRoot $RepoRoot
  $manifest = Get-ChildItem -Path $info.DistRoot -Recurse -Filter "$($info.ModuleName).psd1" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName

  if (-not $manifest) {
    throw "Built module not found under '$($info.DistRoot)'. Run './tasks.ps1 build' first."
  }
  $manifest
}
