<#
.SYNOPSIS
Remove the last of the template scaffolding from a prepared repository.

.DESCRIPTION
Once './tasks.ps1 prepare' has run and the repository is hardened, the setup machinery has
nothing left to do. This deletes it:

  - Tools/prepare.ps1
  - any scaffolding prepare would normally have removed already (res/, Tools/templates/,
    Tools/platforms/), in case the repo was prepared by hand
  - the 'prepare' and 'cleanup' entries in tasks.ps1, and the -Platform parameter that only
    prepare used
  - the prepare/cleanup rows in Tools/README.md
  - itself

Run it once, from the repo root:

  ./tasks.ps1 cleanup

It refuses to run on a repository that has not been prepared, and reports that there is
nothing to do if it has already run.

What it deliberately KEEPS:

  - module.psd1, because install_dev_requirements.ps1 still reads ModuleRequiredModules from
    it and the release workflow still reads ModuleName
  - Docs/HARDENING.md, which documents the live settings of this repository rather than the
    template, and is linked from README.md
#>

$ErrorActionPreference = 'Stop'

. $(Join-Path $PSScriptRoot 'module_info.ps1')

$repoRoot = Split-Path -Parent $PSScriptRoot
$preparePath = Join-Path $PSScriptRoot 'prepare.ps1'
$selfPath = Join-Path $PSScriptRoot 'cleanup.ps1'
$tasksPath = Join-Path $repoRoot 'tasks.ps1'
$toolsReadmePath = Join-Path $PSScriptRoot 'README.md'

function Remove-Block {
  <#
    Cut one exact block out of a file's text. Throws when the block is missing so a drifted
    file fails loudly rather than being half-edited; pass -Optional for blocks a user may
    reasonably have already removed themselves.
  #>
  param(
    [Parameter(Mandatory)][string]$Content,
    [Parameter(Mandatory)][string]$Block,
    [Parameter(Mandatory)][string]$Description,
    [string]$Replacement = '',
    [switch]$Optional
  )
  if (-not $Content.Contains($Block)) {
    if ($Optional) {
      Write-Warning "cleanup: $Description not found; skipped."
      return $Content
    }
    throw "cleanup: $Description not found in the file. It has been edited by hand - remove the template parts manually."
  }
  $Content.Replace($Block, $Replacement)
}

Push-Location $repoRoot
try {
  Write-Host "--------------------------------"
  Write-Host "Cleaning up template scaffolding..."
  Write-Host "--------------------------------"

  # --- 1) Refuse unless this repo is actually prepared ---------------------------------
  if (Test-Path -LiteralPath (Join-Path $repoRoot (Join-Path 'Source' 'ModuleTemplate.psd1'))) {
    throw "This repository has not been prepared yet. Run './tasks.ps1 prepare' first."
  }
  if (-not (Test-Path -LiteralPath $preparePath)) {
    Write-Host "Nothing to do - cleanup has already run."
    return
  }

  # Get-ModuleInfo throws when build.psd1 does not point at a real manifest, which is the
  # cheapest proof that prepare finished rather than failing halfway.
  $info = Get-ModuleInfo -RepoRoot $repoRoot
  if (-not (Test-Path -LiteralPath $info.SourceManifest)) {
    throw "build.psd1 points at '$($info.SourceManifest)', which does not exist. Fix the repository before cleaning up."
  }
  Write-Host "Module: $($info.ModuleName)"

  # --- 2) Drop scaffolding prepare should already have removed --------------------------
  foreach ($leftover in 'res', (Join-Path 'Tools' 'templates'), (Join-Path 'Tools' 'platforms')) {
    $path = Join-Path $repoRoot $leftover
    if (Test-Path -LiteralPath $path) {
      Remove-Item -LiteralPath $path -Recurse -Force
      Write-Host "Removed '$leftover'."
    }
  }

  # --- 3) Strip prepare and cleanup out of tasks.ps1 ------------------------------------
  $tasks = Get-Content -LiteralPath $tasksPath -Raw
  $nl = if ($tasks -match "`r`n") { "`r`n" } else { "`n" }

  $tasks = Remove-Block -Content $tasks -Description "the task list in tasks.ps1" `
    -Block   "'install_dev_requirements', 'prepare', 'cleanup', 'prepare_release'" `
    -Replacement "'install_dev_requirements', 'prepare_release'"

  $tasks = Remove-Block -Content $tasks -Description "the -Platform parameter in tasks.ps1" `
    -Block ("  [double]`$MinimumPercent = 0,$nl" +
            "$nl" +
            "  # Only used by prepare: overrides ModuleTargetPlatform from module.psd1.$nl" +
            "  # One of the presets in Tools/platforms/ (PowerShell5.1, PowerShell7, PowerShell5.1And7).$nl" +
            "  [string]`$Platform$nl") `
    -Replacement "  [double]`$MinimumPercent = 0$nl"

  $tasks = Remove-Block -Content $tasks -Description "the 'prepare' branch in tasks.ps1" `
    -Block ("  'prepare' {$nl" +
            "    # Splatted so an unset -Platform falls through to ModuleTargetPlatform in module.psd1$nl" +
            "    # rather than passing an empty string.$nl" +
            "    `$prepareArgs = @{}$nl" +
            "    if (`$Platform) { `$prepareArgs.Platform = `$Platform }$nl" +
            "    . `$(Join-Path `"Tools`" `"prepare.ps1`") @prepareArgs$nl" +
            "    break$nl" +
            "  }$nl")

  $tasks = Remove-Block -Content $tasks -Description "the 'cleanup' branch in tasks.ps1" `
    -Block ("  'cleanup' {$nl" +
            "    . `$(Join-Path `"Tools`" `"cleanup.ps1`")$nl" +
            "    break$nl" +
            "  }$nl")

  Set-Content -LiteralPath $tasksPath -Value $tasks -NoNewline
  Write-Host "tasks.ps1: 'prepare' and 'cleanup' removed."

  # --- 4) Prune the rows for things that no longer exist from Tools/README.md -----------
  # Optional throughout: this file is documentation the user is free to rewrite, and a
  # missing row is not a reason to fail a cleanup that has already deleted files.
  if (Test-Path -LiteralPath $toolsReadmePath) {
    $toolsReadme = Get-Content -LiteralPath $toolsReadmePath -Raw

    # The paragraph describing what prepare overwrites is actively misleading once prepare is
    # gone, so it goes as a whole block before the per-line pass. Single-quoted here-string:
    # the text is full of backticks, which would otherwise be escape characters.
    $destructiveNote = @'
**`prepare` is destructive by design.** It overwrites `README.md`, `CHANGELOG.md`,
`Tools/PSScriptAnalyzer.psd1` and `.github/workflows/ci.yml`, and deletes `res/`,
`Tools/templates/` and `Tools/platforms/`. Run it on a fresh clone, before you have written
anything.

'@ -replace "`r`n", $nl
    $toolsReadme = Remove-Block -Content $toolsReadme -Optional `
      -Description "the 'prepare is destructive' note in Tools/README.md" `
      -Block $destructiveNote

    $lines = @($toolsReadme -split "`r?`n")
    # Rows and usage lines for files that no longer exist. platforms/ and templates/ are
    # already gone by prepare's own hand, so their rows are stale too.
    $dropPrefixes = @(
      './tasks.ps1 prepare  '
      './tasks.ps1 cleanup'
      '| `prepare.ps1` |'
      '| `cleanup.ps1` |'
      '| `platforms/` |'
      '| `templates/` |'
    )
    $kept = $lines | Where-Object {
      $line = $_
      -not ($dropPrefixes | Where-Object { $line.TrimStart().StartsWith($_) })
    }
    if ($kept.Count -ne $lines.Count) {
      Set-Content -LiteralPath $toolsReadmePath -Value ($kept -join $nl) -NoNewline
      Write-Host "Tools/README.md: $($lines.Count - $kept.Count) obsolete line(s) removed."
    } else {
      Write-Warning "Tools/README.md: nothing matched the expected prepare/cleanup rows; review it by hand."
    }
    Write-Warning "Tools/README.md still describes 'prepare' in its Notes and Target platforms sections; trim those by hand if you want them gone."
  }

  # --- 5) Delete prepare and this script ------------------------------------------------
  # PowerShell parses a script fully before running it, so removing this file mid-run is safe.
  Remove-Item -LiteralPath $preparePath -Force
  Write-Host "Removed 'Tools/prepare.ps1'."
  Remove-Item -LiteralPath $selfPath -Force
  Write-Host "Removed 'Tools/cleanup.ps1'."

  Write-Host "--------------------------------"
  Write-Host "Cleanup complete"
  Write-Host "--------------------------------"
  Write-Host "Review the diff and commit. 'module.psd1' and 'Docs/HARDENING.md' were kept on"
  Write-Host "purpose: the tooling and the release workflow still read the first, and the"
  Write-Host "second documents this repository's own GitHub settings."
} finally {
  Pop-Location
}
