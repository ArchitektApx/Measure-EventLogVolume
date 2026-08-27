# Runs the Pester suite with code coverage against the BUILT module and prints every missed
# command, so a gap can be traced back to a specific line.
#
# Usage (from the repo root):
#   ./tasks.ps1 coverage [-MinimumPercent 90]
#   pwsh -NoProfile -NonInteractive -ExecutionPolicy Bypass -File Tools/coverage.ps1
#
# Coverage is measured per host, and anything that runs in a child process reads as missed
# because the instrumentation cannot follow it. Compare hosts before calling a line untested.

param(
  # Exit non-zero when coverage falls below this percentage. 0 disables the gate.
  [double]$MinimumPercent = 0
)

$ErrorActionPreference = 'Stop'

. $(Join-Path $PSScriptRoot 'module_info.ps1')
$info = Get-ModuleInfo

# Cover the built .psm1 (the artifact a user installs), not the Source/ files it was
# concatenated from.
$psm1 = (Get-ChildItem -Path $info.DistRoot -Recurse -Filter "$($info.ModuleName).psm1" -ErrorAction SilentlyContinue |
  Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
if (-not $psm1) { throw "Built module not found under '$($info.DistRoot)'. Run './tasks.ps1 build' first." }

Remove-Module Pester -Force -ErrorAction SilentlyContinue
Import-Module Pester -MinimumVersion 5.0.0 -Force

$c = New-PesterConfiguration
$c.Run.Path = Join-Path $info.RepoRoot 'Tests'
$c.Run.PassThru = $true
$c.Output.Verbosity = 'None'
$c.CodeCoverage.Enabled = $true
$c.CodeCoverage.Path = $psm1

$r = Invoke-Pester -Configuration $c
$cc = $r.CodeCoverage
$pct = if ($cc.CommandsAnalyzedCount) { $cc.CommandsExecutedCount / $cc.CommandsAnalyzedCount * 100 } else { 0 }

Write-Host ("Tests: {0} passed, {1} failed" -f $r.PassedCount, $r.FailedCount)
Write-Host ("Coverage: {0}/{1} = {2:N1}%" -f $cc.CommandsExecutedCount, $cc.CommandsAnalyzedCount, $pct)
if ($cc.CommandsMissed.Count) {
  Write-Host "--- Missed ---"
  $cc.CommandsMissed | ForEach-Object { Write-Host ("  {0}: {1}" -f $_.Line, $_.Command) }
}

if ($r.FailedCount -gt 0) { exit 1 }
if ($pct -lt $MinimumPercent) {
  Write-Host ("Coverage {0:N1}% is below the {1:N1}% threshold." -f $pct, $MinimumPercent)
  exit 1
}
