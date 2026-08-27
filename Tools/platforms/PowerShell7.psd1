@{
  # PowerShell 7+ only, cross-platform. Pick this for a module that may use post-5.1 syntax
  # (ternaries, null-coalescing, 3-argument Join-Path) and does not need to load on Windows
  # PowerShell.
  Description = 'PowerShell 7+ only (Core edition, Windows/Linux/macOS)'

  # Prose form of the same thing, for the generated module README. Kept separate from
  # Description: that one labels the preset, this one addresses the module's users.
  HostSummary = 'PowerShell 7+ on Windows, Linux, and macOS'

  # Manifest defaults. ModuleRequiredPowershellVersion in module.psd1 overrides the version.
  PowerShellVersion    = '7.0.0'
  CompatiblePSEditions = @('Core')

  # Tools/PSScriptAnalyzer.psd1: syntax versions and command profiles for the compatibility
  # pass in Tools/lint.ps1. PSScriptAnalyzer ships no macOS 7.0 profile, so the Linux one
  # stands in for the whole non-Windows side.
  AnalyzerTargetVersions = @('7.0')
  AnalyzerTargetProfiles = @(
    'win-8_x64_10.0.17763.0_7.0.0_x64_3.1.2_core'
    'ubuntu_x64_18.04_7.0.0_x64_3.1.2_core'
  )

  # .github/workflows/ci.yml matrix. 'host' selects the runtime on the runner:
  # 'powershell' = Windows PowerShell 5.1, 'pwsh' = PowerShell 7+.
  CiMatrix = @(
    @{ os = 'windows-latest'; host = 'pwsh'; name = 'win / pwsh 7';   modulePath = '~\Documents\PowerShell\Modules' }
    @{ os = 'ubuntu-latest';  host = 'pwsh'; name = 'linux / pwsh 7'; modulePath = '~/.local/share/powershell/Modules' }
    @{ os = 'macos-latest';   host = 'pwsh'; name = 'macos / pwsh 7'; modulePath = '~/.local/share/powershell/Modules' }
  )
}
