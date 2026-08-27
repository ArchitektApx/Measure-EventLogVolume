<#
.SYNOPSIS
Turn the module template into your own module.

.DESCRIPTION
Reads module.psd1, renames the template's manifest and root module, stamps every template
placeholder (manifest fields, build.psd1, LICENSE) with your values, generates the lint
ruleset and CI matrix for the chosen target platform, renders a fresh README.md and
CHANGELOG.md for the module, removes the template-only scaffolding, and installs the
development requirements.

Run this once, from the repo root, after editing module.psd1:

  ./tasks.ps1 prepare
  ./tasks.ps1 prepare -Platform PowerShell7

It refuses to run a second time: once Source/ModuleTemplate.psd1 has been renamed there is
nothing left to prepare.

.PARAMETER Platform
Which target-platform preset from Tools/platforms/ to apply. Overrides
ModuleTargetPlatform in module.psd1 when given.
#>

param(
  [string]$Platform
)

$ErrorActionPreference = 'Stop'

# What the template ships as, and therefore what has to be replaced.
$TemplateName = 'ModuleTemplate'

$repoRoot = Split-Path -Parent $PSScriptRoot

function ConvertTo-PsdString {
  <# Quote a value for a .psd1: single-quoted, with embedded quotes doubled. #>
  param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)
  "'" + ($Value -replace "'", "''") + "'"
}

function Set-PsdKey {
  <#
    Replace a 'Key = <value>' assignment in a .psd1, anchored at the start of a line so the
    '# Key ...' comment above it is left alone. Throws when the key is missing, so a drifted
    template fails loudly instead of silently skipping a field. A MatchEvaluator is used
    rather than -replace because '$' inside a value would otherwise be read as a capture
    group reference.
  #>
  param(
    [Parameter(Mandatory)][string]$Content,
    [Parameter(Mandatory)][string]$Key,
    [Parameter(Mandatory)][string]$Value
  )
  $regex = [regex]::new("(?m)^(\s*$([regex]::Escape($Key))\s*=\s*).*$")
  if (-not $regex.IsMatch($Content)) { throw "Manifest key '$Key' not found - the template manifest has drifted." }
  $regex.Replace($Content, { param($m) $m.Groups[1].Value + $Value }, 1)
}

function Set-PsdComment {
  <# Same idea for the generated header comments, but a missing line is not fatal. #>
  param(
    [Parameter(Mandatory)][string]$Content,
    [Parameter(Mandatory)][string]$Pattern,
    [Parameter(Mandatory)][string]$Value
  )
  [regex]::new($Pattern).Replace($Content, { $Value }, 1)
}

function Expand-TemplateFile {
  <#
    Render one Tools/templates file, substituting {{Placeholders}}. Writes to the repo root
    under the same name unless -Destination says otherwise.

    Note the ci.yml template also contains GitHub Actions '${{ matrix.os }}' expressions.
    Those are '${{...}}', not '{{...}}', so they survive substitution untouched - but the
    leftover check below has to allow them, hence the '(?<!\$)' guard.
  #>
  param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][hashtable]$Values,
    [string]$Destination
  )
  $source = Join-Path (Join-Path $PSScriptRoot 'templates') $Name
  if (-not (Test-Path -LiteralPath $source)) { throw "Template '$source' not found." }
  $text = Get-Content -LiteralPath $source -Raw
  foreach ($key in $Values.Keys) {
    $text = $text.Replace("{{$key}}", [string]$Values[$key])
  }
  $leftover = [regex]::Match($text, '(?<!\$)\{\{(\w+)\}\}')
  if ($leftover.Success) { throw "Template '$Name' has an unsubstituted placeholder: $($leftover.Value)" }

  $target = if ($Destination) { Join-Path $repoRoot $Destination } else { Join-Path $repoRoot $Name }
  $targetDir = Split-Path -Parent $target
  if ($targetDir -and -not (Test-Path -LiteralPath $targetDir)) {
    New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
  }
  Set-Content -LiteralPath $target -Value $text -NoNewline
  Write-Host "$(if ($Destination) { $Destination } else { $Name }) written."
}

function Get-DefaultBranchName {
  <#
    The branch this checkout is on, used for the LicenseUri and the release instructions in
    the generated README. symbolic-ref (not rev-parse) because it also answers correctly on a
    fresh repo with no commits yet, where HEAD points at an unborn branch.

    Falls back to the template's own default when git is missing, the directory is not a
    repository, or HEAD is detached, since none of those give a meaningful branch name.
  #>
  param([string]$Fallback = 'master')

  $branch = $null
  try {
    $global:LASTEXITCODE = 0
    $branch = & git -C $repoRoot symbolic-ref --short HEAD 2>$null
    if ($LASTEXITCODE -ne 0) { $branch = $null }
  } catch {
    $branch = $null
  }

  if ([string]::IsNullOrWhiteSpace($branch) -or $branch -match '\s') {
    Write-Warning "Could not determine the current git branch; using '$Fallback' in the README and LicenseUri."
    return $Fallback
  }
  $branch.Trim()
}

function Get-PlatformPreset {
  <#
    Load one Tools/platforms/<Name>.psd1 and check it carries every key prepare consumes,
    so a hand-written preset fails here rather than producing a half-rendered ci.yml.
  #>
  param([Parameter(Mandatory)][string]$Name)

  $dir = Join-Path $PSScriptRoot 'platforms'
  $path = Join-Path $dir "$Name.psd1"
  if (-not (Test-Path -LiteralPath $path)) {
    $available = (Get-ChildItem -Path $dir -Filter '*.psd1' | ForEach-Object BaseName | Sort-Object) -join ', '
    throw "Unknown target platform '$Name'. Available: $available."
  }

  $preset = Import-PowerShellDataFile -LiteralPath $path
  foreach ($key in 'Description', 'HostSummary', 'PowerShellVersion', 'CompatiblePSEditions',
                   'AnalyzerTargetVersions', 'AnalyzerTargetProfiles', 'CiMatrix') {
    if (-not $preset.$key) { throw "Platform preset '$Name' is missing '$key'." }
  }
  $preset
}

function ConvertTo-CiMatrixYaml {
  <#
    Render the preset's CiMatrix as the 'include:' entries of the ci.yml matrix. Flow
    mappings keep each host on one logical line; modulePath is wrapped onto a continuation
    line because the Windows paths contain backslashes and get long.
  #>
  param([Parameter(Mandatory)][object[]]$Matrix)

  $lines = foreach ($entry in $Matrix) {
    foreach ($key in 'os', 'host', 'name', 'modulePath') {
      if (-not $entry.$key) { throw "CI matrix entry is missing '$key'." }
    }
    # Single-quoted YAML scalars: the only escape is a doubled quote.
    $name = $entry.name -replace "'", "''"
    $modulePath = $entry.modulePath -replace "'", "''"
    "          - { os: $($entry.os), host: $($entry.host), name: '$name',"
    "              modulePath: '$modulePath' }"
  }
  $lines -join "`n"
}

Push-Location $repoRoot
try {
  Write-Host "--------------------------------"
  Write-Host "Preparing module..."
  Write-Host "--------------------------------"

  $def = Import-PowerShellDataFile -LiteralPath 'module.psd1'

  # --- 1) Validate module.psd1 ---------------------------------------------------------
  # Note: -contains is a collection operator and is always false against a string, so the
  # whitespace check has to be a regex match.
  foreach ($key in 'ModuleName', 'ModuleDescription', 'ModuleAuthor', 'ModuleCompanyName',
                   'ModuleProjectUri') {
    if ([string]::IsNullOrWhiteSpace($def.$key)) { throw "module.psd1: '$key' is empty." }
  }
  if ($def.ModuleName -match '\s') { throw "module.psd1: ModuleName must not contain whitespace." }
  if ($def.ModuleName -notmatch '^[A-Za-z][A-Za-z0-9._-]*$') {
    throw "module.psd1: ModuleName '$($def.ModuleName)' is not a valid module name (start with a letter; letters, digits, '.', '_' and '-' only)."
  }
  if ($def.ModuleName -eq $TemplateName) {
    throw "module.psd1: ModuleName is still '$TemplateName'. Set your own module name before running prepare."
  }
  if ($def.ModuleProjectUri -notmatch '^https?://\S+$') {
    throw "module.psd1: ModuleProjectUri '$($def.ModuleProjectUri)' is not an http(s) URL."
  }
  $projectUri = ([string]$def.ModuleProjectUri).TrimEnd('/')
  $defaultBranch = Get-DefaultBranchName
  Write-Host "Default branch: $defaultBranch"

  # --- 1b) Resolve the target platform -------------------------------------------------
  # The -Platform parameter wins over module.psd1 so a preset can be tried without editing
  # the file first.
  $platformName = if ($Platform) { $Platform } else { [string]$def.ModuleTargetPlatform }
  if ([string]::IsNullOrWhiteSpace($platformName)) {
    throw "No target platform. Set ModuleTargetPlatform in module.psd1 or pass -Platform."
  }
  $preset = Get-PlatformPreset -Name $platformName

  # The preset supplies the minimum PowerShell version; module.psd1 may pin a higher one
  # (7.4 rather than the preset's 7.0, say).
  $psVersion = if ([string]::IsNullOrWhiteSpace($def.ModuleRequiredPowershellVersion)) {
    [string]$preset.PowerShellVersion
  } else {
    [string]$def.ModuleRequiredPowershellVersion
  }
  $parsedVersion = $null
  if (-not [version]::TryParse($psVersion, [ref]$parsedVersion)) {
    throw "module.psd1: ModuleRequiredPowershellVersion '$psVersion' is not a valid version."
  }
  Write-Host "Target platform: $platformName - $($preset.Description)"
  Write-Host "PowerShellVersion: $psVersion, CompatiblePSEditions: $($preset.CompatiblePSEditions -join ', ')"

  # --- 2) Rename the template's manifest and root module -------------------------------
  $sourceDir = Join-Path $repoRoot 'Source'
  $oldManifest = Join-Path $sourceDir "$TemplateName.psd1"
  $oldRootModule = Join-Path $sourceDir "$TemplateName.psm1"
  if (-not (Test-Path -LiteralPath $oldManifest)) {
    throw "'$oldManifest' not found - this repository has already been prepared."
  }
  Rename-Item -LiteralPath $oldManifest -NewName "$($def.ModuleName).psd1"
  Rename-Item -LiteralPath $oldRootModule -NewName "$($def.ModuleName).psm1"
  $manifestPath = Join-Path $sourceDir "$($def.ModuleName).psd1"
  Write-Host "Source/$TemplateName.ps[dm]1 renamed to $($def.ModuleName).ps[dm]1."

  # --- 3) Stamp the module manifest ----------------------------------------------------
  # Edited as text rather than via Update-ModuleManifest: that cmdlet runs
  # Test-ModuleManifest internally, which fails on a manifest whose module has not been
  # built yet - which is exactly the state prepare runs in.
  $year = (Get-Date).Year
  $editions = ($preset.CompatiblePSEditions | ForEach-Object { ConvertTo-PsdString $_ }) -join ', '

  $manifest = Get-Content -LiteralPath $manifestPath -Raw
  $manifest = Set-PsdKey $manifest 'RootModule'           (ConvertTo-PsdString "$($def.ModuleName).psm1")
  $manifest = Set-PsdKey $manifest 'GUID'                 (ConvertTo-PsdString (New-Guid).Guid)
  $manifest = Set-PsdKey $manifest 'CompatiblePSEditions' $editions
  $manifest = Set-PsdKey $manifest 'Author'               (ConvertTo-PsdString $def.ModuleAuthor)
  $manifest = Set-PsdKey $manifest 'CompanyName'          (ConvertTo-PsdString $def.ModuleCompanyName)
  $manifest = Set-PsdKey $manifest 'Copyright'            (ConvertTo-PsdString "Copyright $year $($def.ModuleCompanyName)")
  $manifest = Set-PsdKey $manifest 'Description'          (ConvertTo-PsdString $def.ModuleDescription)
  $manifest = Set-PsdKey $manifest 'PowerShellVersion'    (ConvertTo-PsdString $psVersion)
  $manifest = Set-PsdKey $manifest 'ProjectUri'           (ConvertTo-PsdString $projectUri)
  $manifest = Set-PsdKey $manifest 'LicenseUri'           (ConvertTo-PsdString "$projectUri/blob/$defaultBranch/LICENSE")
  # Placeholder tags would otherwise ship to the Gallery as-is.
  $manifest = Set-PsdKey $manifest 'Tags'                 '@()'

  $manifest = Set-PsdComment $manifest "(?m)^# Module manifest for module '.*'$" "# Module manifest for module '$($def.ModuleName)'"
  $manifest = Set-PsdComment $manifest '(?m)^# Generated by: .*$'                "# Generated by: $($def.ModuleAuthor)"
  $manifest = Set-PsdComment $manifest '(?m)^# Generated on: .*$'                "# Generated on: $(Get-Date -Format 'yyyy-MM-dd')"

  Set-Content -LiteralPath $manifestPath -Value $manifest -NoNewline

  # Prove the result is still a readable data file before moving on.
  $written = Import-PowerShellDataFile -LiteralPath $manifestPath
  if ($written.RootModule -ne "$($def.ModuleName).psm1") {
    throw "Manifest verification failed: RootModule is '$($written.RootModule)'."
  }
  Write-Host "Source/$($def.ModuleName).psd1 stamped."

  # --- 4) Point build.psd1 at the renamed manifest --------------------------------------
  $build = Get-Content -LiteralPath 'build.psd1' -Raw
  $build = $build.Replace("Source\$TemplateName.psd1", "Source\$($def.ModuleName).psd1")
  $build = $build.Replace("Dist\$TemplateName", "Dist\$($def.ModuleName)")
  Set-Content -LiteralPath 'build.psd1' -Value $build -NoNewline
  $semVer = (Import-PowerShellDataFile -LiteralPath 'build.psd1').SemVer
  Write-Host "build.psd1 adapted."

  # --- 5) Stamp the LICENSE copyright holder --------------------------------------------
  if (Test-Path -LiteralPath 'LICENSE') {
    $license = Get-Content -LiteralPath 'LICENSE' -Raw
    $licenseRegex = [regex]::new('(?m)^(Copyright \(c\) )\d{4}(?: .*)?$')
    if ($licenseRegex.IsMatch($license)) {
      $holder = $def.ModuleCompanyName
      $license = $licenseRegex.Replace($license, { param($m) "$($m.Groups[1].Value)$year $holder" }, 1)
      Set-Content -LiteralPath 'LICENSE' -Value $license -NoNewline
      Write-Host "LICENSE copyright set to '$year $holder'."
    } else {
      Write-Warning "LICENSE: no 'Copyright (c) <year> <holder>' line found; left unchanged."
    }
  }

  # --- 6) Render the module's own README and CHANGELOG ----------------------------------
  # These OVERWRITE the template repository's versions, which document the template rather
  # than your module.
  $values = @{
    ModuleName        = $def.ModuleName
    ModuleDescription = $def.ModuleDescription
    ProjectUri        = $projectUri
    SemVer            = $semVer
    Year              = $year
    CompanyName       = $def.ModuleCompanyName
    Author            = $def.ModuleAuthor
    Date              = (Get-Date -Format 'yyyy-MM-dd')
    DefaultBranch     = $defaultBranch
    # Built from the preset plus the resolved version, so it stays right when
    # ModuleRequiredPowershellVersion pins a higher minimum than the preset's default.
    Requirements      = "Runs on $($preset.HostSummary). The manifest requires PowerShell $psVersion or later."
  }
  Expand-TemplateFile -Name 'README.md'    -Values $values
  Expand-TemplateFile -Name 'CHANGELOG.md' -Values $values

  # --- 7) Generate the lint ruleset and the CI matrix for the target platform -----------
  # Both are plain files afterwards: nothing regenerates them, so retargeting later means
  # editing these two by hand (see Tools/README.md).
  $platformValues = @{
    PlatformName        = $platformName
    PlatformDescription = $preset.Description
    TargetVersions      = ($preset.AnalyzerTargetVersions | ForEach-Object { "'$_'" }) -join ', '
    TargetProfiles      = ($preset.AnalyzerTargetProfiles | ForEach-Object { "              '$_'" }) -join "`n"
    Matrix              = ConvertTo-CiMatrixYaml -Matrix $preset.CiMatrix
  }
  Expand-TemplateFile -Name 'PSScriptAnalyzer.psd1' -Values $platformValues -Destination (Join-Path 'Tools' 'PSScriptAnalyzer.psd1')
  Expand-TemplateFile -Name 'ci.yml' -Values $platformValues -Destination (Join-Path '.github' (Join-Path 'workflows' 'ci.yml'))

  # Prove the generated ruleset is still a readable data file with the expected shape.
  $writtenRules = Import-PowerShellDataFile -LiteralPath (Join-Path $repoRoot (Join-Path 'Tools' 'PSScriptAnalyzer.psd1'))
  $writtenVersions = $writtenRules.Rules.PSUseCompatibleSyntax.TargetVersions
  if (@($writtenVersions).Count -ne @($preset.AnalyzerTargetVersions).Count) {
    throw "Generated Tools/PSScriptAnalyzer.psd1 does not carry the preset's TargetVersions."
  }

  # --- 8) Drop the template-only scaffolding -------------------------------------------
  foreach ($leftover in 'res', (Join-Path 'Tools' 'templates'), (Join-Path 'Tools' 'platforms')) {
    $path = Join-Path $repoRoot $leftover
    if (Test-Path -LiteralPath $path) {
      Remove-Item -LiteralPath $path -Recurse -Force
      Write-Host "Removed template-only '$leftover'."
    }
  }

  Write-Host "--------------------------------"
  Write-Host "Module prepared successfully"
  Write-Host "--------------------------------"
} catch {
  Write-Host "--------------------------------"
  Write-Host "Module preparation failed"
  Write-Host "--------------------------------"
  throw
} finally {
  Pop-Location
}

Write-Host "--------------------------------"
Write-Host "Installing required modules..."
Write-Host "--------------------------------"
. $(Join-Path $PSScriptRoot 'install_dev_requirements.ps1')

Write-Host "--------------------------------"
Write-Host "Next: add functions under Source/Public, then run './tasks.ps1 build' and './tasks.ps1 test'."
Write-Host "Work through Docs/HARDENING.md before the first release tag."
Write-Host "Then run './tasks.ps1 cleanup' to delete the setup machinery you no longer need."
Write-Host "--------------------------------"
