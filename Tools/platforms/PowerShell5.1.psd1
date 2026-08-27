@{
  # Windows PowerShell 5.1 only. Pick this for a module that targets the .NET Framework host
  # shipped in every Windows install and is not expected to run on pwsh 7.
  Description = 'Windows PowerShell 5.1 only (Desktop edition, Windows only)'

  # Prose form of the same thing, for the generated module README. Kept separate from
  # Description: that one labels the preset, this one addresses the module's users.
  HostSummary = 'Windows PowerShell 5.1'

  # Manifest defaults. ModuleRequiredPowershellVersion in module.psd1 overrides the version.
  PowerShellVersion    = '5.1.0'
  CompatiblePSEditions = @('Desktop')

  # Tools/PSScriptAnalyzer.psd1: syntax versions and command profiles for the compatibility
  # pass in Tools/lint.ps1.
  AnalyzerTargetVersions = @('5.1')
  AnalyzerTargetProfiles = @(
    'win-8_x64_10.0.17763.0_5.1.17763.316_x64_4.0.30319.42000_framework'
  )

  # .github/workflows/ci.yml matrix. 'host' selects the runtime on the runner:
  # 'powershell' = Windows PowerShell 5.1, 'pwsh' = PowerShell 7+.
  CiMatrix = @(
    @{ os = 'windows-latest'; host = 'powershell'; name = 'win / WinPS 5.1'; modulePath = '~\Documents\WindowsPowerShell\Modules' }
  )
}
