# Shared by every *.Tests.ps1: import the BUILT module from Dist (NOT the source).
# ModuleBuilder only exports the public functions in the built module, so tests must run
# against the build output, the same artifact a user installs.
#
# Get-ModuleInfo / Get-BuiltManifestPath come from Tools/module_info.ps1, which resolves the
# module's name from build.psd1 - no name is hardcoded here, so this keeps working after
# './tasks.ps1 prepare' renames everything.
. (Join-Path (Join-Path (Split-Path -Parent $PSScriptRoot) 'Tools') 'module_info.ps1')

function Import-BuiltModule {
  Import-Module (Get-BuiltManifestPath) -Force
}

# Single definition of the host check used by -Skip: expressions, which Pester evaluates at
# DISCOVERY time - so this must work before any BeforeAll runs, and on Windows PowerShell 5.1
# where $IsWindows does not exist.
function Test-OnWindowsHost {
  [OutputType([bool])]
  param()
  ($PSVersionTable.PSEdition -eq 'Desktop') -or [bool]$IsWindows
}
