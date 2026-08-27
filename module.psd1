@{
  # The name of the module, must not contain spaces
  ModuleName = "ModuleTemplate"
  # The description of the module
  ModuleDescription = "Module Description"
  # Which PowerShell hosts the module targets. One of the presets in Tools/platforms/:
  #   PowerShell5.1      - Windows PowerShell 5.1 only (Desktop, Windows)
  #   PowerShell7        - PowerShell 7+ only (Core, Windows/Linux/macOS)
  #   PowerShell5.1And7  - both (widest reach, strictest lint)
  # './tasks.ps1 prepare' uses this to set CompatiblePSEditions and PowerShellVersion in the
  # manifest, and to generate Tools/PSScriptAnalyzer.psd1 and the .github/workflows/ci.yml
  # matrix. Override for one run with './tasks.ps1 prepare -Platform PowerShell7'.
  ModuleTargetPlatform = "PowerShell5.1And7"
  # Optional: pin a higher minimum PowerShell version than the platform's default
  # (e.g. '7.4.0' with the PowerShell7 platform). Leave empty to use the platform default.
  ModuleRequiredPowershellVersion = ''
  # Extra modules your module needs at DEVELOPMENT time, on top of the fixed base set
  # (ModuleBuilder, Configuration, Pester 5+, PSScriptAnalyzer) that Tools/ always installs.
  # Accepts plain names or @{ Name = 'Foo'; MinimumVersion = '2.0.0' } hashtables.
  ModuleRequiredModules = @()
  # The author of the module
  ModuleAuthor = "Module Author"
  # The company name of the module, also used as the LICENSE copyright holder
  ModuleCompanyName = "ArchitektApx"
  # The repository this module lives in. Becomes ProjectUri/LicenseUri in the manifest and
  # the compare links in CHANGELOG.md, so set it before running './tasks.ps1 prepare'.
  ModuleProjectUri = "https://github.com/ArchitektApx/ModuleTemplate"
}
