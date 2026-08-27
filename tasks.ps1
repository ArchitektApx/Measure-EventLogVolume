param(
  # Positions are explicit on purpose: as soon as ONE parameter declares a Position, the
  # others stop binding positionally, and './tasks.ps1 test' would silently run the default.
  [Parameter(Position = 0)]
  [ValidateSet('build', 'test', 'lint', 'coverage', 'install_dev_requirements', 'prepare', 'cleanup', 'prepare_release')]
  [string]$Task = 'build',

  # Only used by prepare_release: ./tasks.ps1 prepare_release 1.1.0
  [Parameter(Position = 1)]
  [string]$Version,

  # Only used by coverage: fail the run when coverage drops below this percentage.
  [double]$MinimumPercent = 0,

  # Only used by prepare: overrides ModuleTargetPlatform from module.psd1.
  # One of the presets in Tools/platforms/ (PowerShell5.1, PowerShell7, PowerShell5.1And7).
  [string]$Platform
)

switch ($Task) {
  'build' {
    . $(Join-Path "Tools" "build.ps1")
    break
  }
  'test' {
    . $(Join-Path "Tools" "tests.ps1")
    break
  }
  'lint' {
    . $(Join-Path "Tools" "lint.ps1")
    break
  }
  'coverage' {
    . $(Join-Path "Tools" "coverage.ps1") -MinimumPercent $MinimumPercent
    break
  }
  'install_dev_requirements' {
    . $(Join-Path "Tools" "install_dev_requirements.ps1")
    break
  }
  'prepare' {
    # Splatted so an unset -Platform falls through to ModuleTargetPlatform in module.psd1
    # rather than passing an empty string.
    $prepareArgs = @{}
    if ($Platform) { $prepareArgs.Platform = $Platform }
    . $(Join-Path "Tools" "prepare.ps1") @prepareArgs
    break
  }
  'cleanup' {
    . $(Join-Path "Tools" "cleanup.ps1")
    break
  }
  'prepare_release' {
    if (-not $Version) {
      # throw, not Write-Error: the process must exit non-zero so CI cannot mistake a
      # botched invocation for a prepared release.
      throw "prepare_release needs a version: ./tasks.ps1 prepare_release <x.y.z>"
    }
    . $(Join-Path "Tools" "prepare_release.ps1") -Version $Version
    break
  }
  default {
    throw "Invalid task: $Task"
  }
}
