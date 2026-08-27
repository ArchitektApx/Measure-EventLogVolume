@{
  # Both hosts. The widest reach and the strictest lint: a command or syntax form has to
  # exist on Windows PowerShell 5.1 AND PowerShell 7 to pass. This is the template default.
  Description = 'Windows PowerShell 5.1 and PowerShell 7+ (Desktop and Core, Windows/Linux/macOS)'

  # Prose form of the same thing, for the generated module README. Kept separate from
  # Description: that one labels the preset, this one addresses the module's users.
  HostSummary = 'Windows PowerShell 5.1, or PowerShell 7+ on Windows, Linux, and macOS'

  # Manifest defaults. ModuleRequiredPowershellVersion in module.psd1 overrides the version.
  # 5.1 is the floor: it is the older of the two hosts.
  PowerShellVersion    = '5.1.0'
  CompatiblePSEditions = @('Core', 'Desktop')

  # Tools/PSScriptAnalyzer.psd1: syntax versions and command profiles for the compatibility
  # pass in Tools/lint.ps1. PSScriptAnalyzer ships no macOS 7.0 profile, so the Linux one
  # stands in for the whole non-Windows side.
  AnalyzerTargetVersions = @('5.1', '7.0')
  AnalyzerTargetProfiles = @(
    'win-8_x64_10.0.17763.0_5.1.17763.316_x64_4.0.30319.42000_framework'
    'win-8_x64_10.0.17763.0_7.0.0_x64_3.1.2_core'
    'ubuntu_x64_18.04_7.0.0_x64_3.1.2_core'
  )

  # .github/workflows/ci.yml matrix. 'host' selects the runtime on the runner:
  # 'powershell' = Windows PowerShell 5.1, 'pwsh' = PowerShell 7+.
  CiMatrix = @(
    @{ os = 'windows-latest'; host = 'powershell'; name = 'win / WinPS 5.1'; modulePath = '~\Documents\WindowsPowerShell\Modules' }
    @{ os = 'windows-latest'; host = 'pwsh';       name = 'win / pwsh 7';   modulePath = '~\Documents\PowerShell\Modules' }
    @{ os = 'ubuntu-latest';  host = 'pwsh';       name = 'linux / pwsh 7'; modulePath = '~/.local/share/powershell/Modules' }
    @{ os = 'macos-latest';   host = 'pwsh';       name = 'macos / pwsh 7'; modulePath = '~/.local/share/powershell/Modules' }
  )
}
