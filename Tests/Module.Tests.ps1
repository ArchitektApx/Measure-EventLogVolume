# Example suite. It only asserts things that hold for an empty module, so it is green on a
# fresh clone and 'tests.ps1' has something to run. Keep it, extend it, or replace it as you
# add functions under Source/Public - one <Area>.Tests.ps1 per area is the usual shape.
BeforeAll {
  . $PSScriptRoot/_TestHelpers.ps1
  Import-BuiltModule
}

Describe 'Built module' {
  It 'produced a manifest under Dist' {
    Get-BuiltManifestPath | Should -Exist
  }

  It 'has a valid manifest' {
    { Test-ModuleManifest -Path (Get-BuiltManifestPath) } | Should -Not -Throw
  }

  It 'imports' {
    Get-Module -Name (Get-ModuleInfo).ModuleName | Should -Not -BeNullOrEmpty
  }
}
