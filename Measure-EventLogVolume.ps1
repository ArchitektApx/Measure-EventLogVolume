#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
    Estimate the Volume of Event Logs on a Windows Machine
    for example to plan for Microsoft Sentinel ingestion.

.PARAMETER LogName
    [string[]]
    The name(s) of the Event Log(s) to measure.
    Default is 'Application' and 'Security'.

.PARAMETER KeepHistory
    [switch]
    For machines with extremly high log volumes where the event log is rolling over,
    and only a limited time window is available, this flag can set to save
    results to a temp file and re-use this data on subsequent runs to
    improve the accuracy of the results by calculating a running average over 
    all known data.

.PARAMETER HistoryFilePath
    [string]
    The path to the file that will store the historical data.
    Default is [system.io.path]::GetTempPath()

.PARAMETER TempFileName
    [string]
    The name of the file that will store the historical data.
    Default is 'Measure-EventLogVolume_HistoryData.json'.

.PARAMETER PurgeHistory
    [switch]
    If set, all historical data will be deleted.

.EXAMPLE
    > .\Measure-EventLogVolume.ps1
    === Average Log Volume on MyServer ===

    🗂 Application Log
    Oldest Record:  07/19/2022 09:58:14
    Newest Record:  05/14/2025 16:43:08
    Logs per Hour:  4.95
    Logs per Day:   118.78
    Logs per Week:  831.47
    Logs per Month: 514.72
    MB per Hour:    0
    MB per Day:     0.04
    MB per Week:    0.29
    MB per Month:   0.18

    🔐 Security Log
    Oldest Record:  05/06/2025 07:05:22
    Newest Record:  05/14/2025 16:49:26
    Logs per Hour:  1118.36
    Logs per Day:   26840.66
    Logs per Week:  187884.6
    Logs per Month: 116309.51
    MB per Hour:    0.74
    MB per Day:     17.84
    MB per Week:    124.9
    MB per Month:   77.32

.EXAMPLE
    > .\Measure-EventLogVolume.ps1 -KeepHistory
    === Average Log Volume on MyServer ===

    🗂 Application Log
    Oldest Record:  07/19/2022 09:58:14
    Newest Record:  05/14/2025 16:43:08
    Historical Records:  3
    Logs per Hour:  4.95
    Logs per Day:   118.78
    Logs per Week:  831.47
    Logs per Month: 514.72
    MB per Hour:    0
    MB per Day:     0.04
    MB per Week:    0.29
    MB per Month:   0.18

    🔐 Security Log
    Oldest Record:  05/06/2025 07:05:22
    Newest Record:  05/14/2025 16:49:26
    Historical Records:  3
    Logs per Hour:  1118.36
    Logs per Day:   26840.66
    Logs per Week:  187884.6
    Logs per Month: 116309.51
    MB per Hour:    0.74
    MB per Day:     17.84
    MB per Week:    124.9
    MB per Month:   77.32

.EXAMPLE
    > .\Measure-EventLogVolume.ps1 -LogName 'System' -KeepHistory

.EXAMPLE
    > .\Measure-EventLogVolume.ps1 -KeepHistory -HistoryFilePath 'C:\Temp' -TempFileName 'Measure-EventLogVolume_HistoryData.json'
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string[]]$LogName = @('Application', 'Security'),
    [Parameter(Mandatory = $false)]
    [switch]$KeepHistory,
    [Parameter(Mandatory = $false)]
    [string]$HistoryFilePath = [system.io.path]::GetTempPath(),
    [Parameter(Mandatory = $false)]
    [string]$TempFileName = 'Measure-EventLogVolume_HistoryData.json',
    [Parameter(Mandatory = $false)]
    [switch]$PurgeHistory
)

#region CONSTANTS

$TEMP_FILE_PATH     = [system.io.path]::Combine($HistoryFilePath, $TempFileName)
$DAYS_PER_WEEK      = 7
$WEEKS_PER_MONTH    = 52 / 12

#endregion

#region HELPER FUNCTIONS

function Get-LogStats {
    [OutputType([PSCustomObject])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$LogName
    )

    $LogInfo = Get-WinEvent -ListLog $LogName -ErrorAction SilentlyContinue
    $LogSizeMBValue = if ($LogInfo.FileSize) { $LogInfo.FileSize / 1MB } else { 0 }

    $ParamSplat = @{
        LogName     = $LogName
        MaxEvents   = 1
        ErrorAction = 'SilentlyContinue'
    }
    
    # read only the newest and oldest event to extract the time range so we don't need to parse 
    # thousands of events
    $NewestEvent        = Get-WinEvent @ParamSplat
    $NewestEventTime    = $NewestEvent.TimeCreated
    $OldestEvent        = Get-WinEvent @ParamSplat -Oldest
    $OldestEventTime    = $OldestEvent.TimeCreated
    $TimeRange          = $NewestEventTime - $OldestEventTime

    return [PSCustomObject]@{
        LogName             = $LogName
        LogCount            = $LogInfo.RecordCount
        LogSizeMB           = $LogSizeMBValue
        StartTime           = $OldestEventTime
        EndTime             = $NewestEventTime
        AverageLogsPerHour  = $LogInfo.RecordCount / $TimeRange.TotalHours
        AverageMBPerHour    = ($LogInfo.FileSize / $TimeRange.TotalHours) / 1MB
        AverageLogsPerDay   = $LogInfo.RecordCount / $TimeRange.TotalDays
        AverageMBPerDay     = ($LogInfo.FileSize / $TimeRange.TotalDays) / 1MB
    }
}

function ConvertFrom-PSCustomObjectToHashtable {
<#
.SYNOPSIS
    Helper function to convert a PSCustomObject to a Hashtable.
    Since ConvertFrom-Json has no -AsHashtable parameter in PowerShell 5.1,
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [PSCustomObject]$InputObject
    )

    $Output = @{}
    foreach ($Property in $InputObject.PSObject.Properties) {
        $Output[$Property.Name] = $Property.Value
    }

    return $Output
}

function Get-StatRecordHistory {
    [OutputType([Hashtable])]
    [CmdletBinding()]
    param()

    $Output = @{}

    if (Test-Path $TEMP_FILE_PATH) {
        $Raw        = Get-Content $TEMP_FILE_PATH -Raw
        $JsonObject = ConvertFrom-Json $Raw
        $LogStatsHt = ConvertFrom-PSCustomObjectToHashtable $JsonObject.LogStats
        $Output = [hashtable] $LogStatsHt
    }

    return $Output
}

function Measure-Average {
    [OutputType([double])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [object[]]$InputObjects,
        [Parameter(Mandatory = $false)]
        [string]$Property
    )

    $ParamSplat = @{ Average = $true }
    if ($Property) { $ParamSplat['Property'] = $Property }

    return $InputObjects | Measure-Object @ParamSplat | Select-Object -ExpandProperty Average
    
}

function Get-HistoricalAverage {
    [OutputType([PSCustomObject])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [System.Collections.ArrayList]$StatRecordHistory,
        [Parameter(Mandatory)]
        [string]$LogName
    )

    # calculate the running averages of all the records
    $AvgLogsPerHour     = $StatRecordHistory | Measure-Average -Property AverageLogsPerHour
    $AvgLogMBPerHour    = $StatRecordHistory | Measure-Average -Property AverageMBPerHour
    $AvgLogsPerDay      = $StatRecordHistory | Measure-Average -Property AverageLogsPerDay
    $AvgLogMBPerDay     = $StatRecordHistory | Measure-Average -Property AverageMBPerDay

    # estimate the weekly and monthly averages
    $AvgLogsPerWeek     = $AvgLogsPerDay * $DAYS_PER_WEEK
    $AvgLogMBPerWeek    = $AvgLogMBPerDay * $DAYS_PER_WEEK
    $AvgLogsPerMonth    = $AvgLogsPerWeek * $WEEKS_PER_MONTH
    $AvgLogMBPerMonth   = $AvgLogMBPerWeek * $WEEKS_PER_MONTH

    # get the oldest and newest record in the history
    $OldestRecord = $StatRecordHistory | Sort-Object -Property StartTime | Select-Object -First 1 -ExpandProperty StartTime
    $NewestRecord = $StatRecordHistory | Sort-Object -Property EndTime -Descending | Select-Object -First 1 -ExpandProperty EndTime

    $Output = [PSCustomObject]@{
        LogName             = $LogName
        OldestRecord        = $OldestRecord
        NewestRecord        = $NewestRecord
        HistoricalRecords   = $StatRecordHistory.Count
        AverageLogsPerHour  = [math]::Round($AvgLogsPerHour, 2)
        AverageMBPerHour    = [math]::Round($AvgLogMBPerHour, 2)
        AverageLogsPerDay   = [math]::Round($AvgLogsPerDay, 2)
        AverageMBPerDay     = [math]::Round($AvgLogMBPerDay, 2)
        AverageLogsPerWeek  = [math]::Round($AvgLogsPerWeek, 2)
        AverageMBPerWeek    = [math]::Round($AvgLogMBPerWeek, 2)
        AverageLogsPerMonth = [math]::Round($AvgLogsPerMonth, 2)
        AverageMBPerMonth   = [math]::Round($AvgLogMBPerMonth, 2)
    }

    return $Output
}

function Get-CurrentStats {
    [OutputType([Hashtable])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string[]]$LogName
    )

    $Output = @{}
    foreach ($Name in $LogName) {
        $Output["$Name"] = [System.Collections.ArrayList]@(Get-LogStats -LogName $Name)
    }
    return $Output
}

function Remove-History {
    [CmdletBinding()]
    param()

    if (Test-Path $TEMP_FILE_PATH) {
        Remove-Item $TEMP_FILE_PATH -ErrorAction SilentlyContinue -Force
    }
}
function Write-ConsoleOutput {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [hashtable]$HistoryAverages,
        [Parameter(Mandatory)]
        [string[]]$LogName
    )

    $EmojiMap = @{
        'Application'     = '🗂'
        'Security'        = '🔐'
        'System'          = '💻'
        'Setup'           = '📦'
        'ForwardedEvents' = '📤'
    }

    $StringBuilder = [System.Text.StringBuilder]::new()
    [void] $StringBuilder.AppendLine("=== Average Log Volume on $ENV:COMPUTERNAME ===")
    [void] $StringBuilder.AppendLine('')

    foreach ($LogRecord in $HistoryAverages.GetEnumerator()) {
        # only print the logs that are requested on this run
        if ($LogRecord.Key -in $LogName) {
            # if the EmojiMap is empty trim will remove the space at the beginning of the string
            $Emoji = $EmojiMap["$($LogRecord.Key)"]
            $Title = "$Emoji $($LogRecord.Key) Log".Trim()
            [void] $StringBuilder.AppendLine($Title)
            [void] $StringBuilder.AppendLine("Oldest Record:  $($LogRecord.Value.OldestRecord)")
            [void] $StringBuilder.AppendLine("Newest Record:  $($LogRecord.Value.NewestRecord)")

            if ($LogRecord.Value.HistoricalRecords -gt 1) {
                [void] $StringBuilder.AppendLine("Historical Records:  $($LogRecord.Value.HistoricalRecords)")
            }

            [void] $StringBuilder.AppendLine("Logs per Hour:  $($LogRecord.Value.AverageLogsPerHour)")
            [void] $StringBuilder.AppendLine("Logs per Day:   $($LogRecord.Value.AverageLogsPerDay)")
            [void] $StringBuilder.AppendLine("Logs per Week:  $($LogRecord.Value.AverageLogsPerWeek)")
            [void] $StringBuilder.AppendLine("Logs per Month: $($LogRecord.Value.AverageLogsPerMonth)")

            [void] $StringBuilder.AppendLine("MB per Hour:    $($LogRecord.Value.AverageMBPerHour)")
            [void] $StringBuilder.AppendLine("MB per Day:     $($LogRecord.Value.AverageMBPerDay)")
            [void] $StringBuilder.AppendLine("MB per Week:    $($LogRecord.Value.AverageMBPerWeek)")
            [void] $StringBuilder.AppendLine("MB per Month:   $($LogRecord.Value.AverageMBPerMonth)")
            [void] $StringBuilder.AppendLine([System.Environment]::NewLine)
        }
    }

    Write-Host $StringBuilder.ToString()
    [void] $StringBuilder.Clear()
}

function Test-IsValidLogName {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$LogName
    )

    try {
        Get-WinEvent -ListLog $LogName -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

#endregion

#region MAIN LOGIC

$ValidLogNames = [System.Collections.ArrayList]::new()
foreach ($logNameToValidate in $LogName) { 
    if (Test-IsValidLogName -LogName $logNameToValidate) { [void]$ValidLogNames.Add($logNameToValidate) }
    else {Write-Warning "Invalid or inaccessible log name: '$logNameToValidate'. This log will be skipped." }
}

if ($ValidLogNames.Count -eq 0) {
    Write-Error "No valid log names were provided or found to be accessible. Exiting."
    return
}

if ($PurgeHistory) { Remove-History }

$CurrentStats = Get-CurrentStats -LogName $ValidLogNames

if ($KeepHistory) {
    $LogStatsHistory = Get-StatRecordHistory
    foreach ($LogStat in $LogStatsHistory.GetEnumerator()) {
        if ($CurrentStats.ContainsKey($LogStat.Key)) {
            $CurrentStats["$($LogStat.Key)"].AddRange($LogStat.Value)
        }
        else {
            $CurrentStats["$($LogStat.Key)"] = $LogStat.Value
        }
    }
}

$StatsOutput = [PSCustomObject]@{
    LogStats = $CurrentStats
    Averages = @{}
}

# Calculate averages for the valid log names processed in this run.
foreach ($Name in $ValidLogNames) { 
    if ($CurrentStats.ContainsKey($Name) -and $CurrentStats[$Name].Count -gt 0) {
        # Ensure the key exists and there's data. 
        # Get-HistoricalAverage should ideally be resilient to records with 'Remark' if they have 0 rates.
        $StatsOutput.Averages[$Name] = Get-HistoricalAverage -StatRecordHistory $CurrentStats[$Name] -LogName $Name
    } else {
        Write-Warning "No data available in CurrentStats for log '$Name' to calculate averages. This might be due to earlier retrieval issues."
    }
}

if ($KeepHistory) {
    $StatsOutput | ConvertTo-Json -Depth 10 | Set-Content -Path $TEMP_FILE_PATH -Force
}

$StatsOutput.Averages | Write-ConsoleOutput -LogName $ValidLogNames

#endregion