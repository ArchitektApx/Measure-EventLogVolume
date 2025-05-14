# Measure-EventLogVolume.ps1

## Overview

`Measure-EventLogVolume.ps1` is a PowerShell script designed to estimate the volume of event logs on a Windows machine. This can be particularly useful for capacity planning, such as estimating data ingestion for systems like Microsoft Sentinel or other SIEM solutions.

The script analyzes specified event logs, calculates the rate of log generation (logs per hour/day/week/month), and estimates the data volume in megabytes over the same periods.

## Prerequisites

* **PowerShell Version**: Requires PowerShell 5.1 or higher.
* **Administrator Privileges**: The script must be run as an Administrator to access event log data.

## Parameters

* `LogName` (string[]):
  * Specifies the name(s) of the Event Log(s) to measure.
  * Default: `@('Application', 'Security')`
* `KeepHistory` (switch):
  * If set, the script saves results to a temporary file and re-uses this data on subsequent runs. This calculates a running average, which is useful for logs with high turnover like Security Logs on Domain Controllers in large environments.
* `HistoryFilePath` (string):
  * The path to the directory where the historical data file will be stored.
  * Default: `[System.IO.Path]::GetTempPath()` (System's temporary folder)
* `TempFileName` (string):
  * The name of the JSON file that will store the historical data.
  * Default: `'Measure-EventLogVolume_HistoryData.json'`
* `PurgeHistory` (switch):
  * If set, all previously stored historical data will be deleted before the script runs.
* `WriteAveragesToOutput` (switch):
  * If set, the script outputs the calculated averages as a JSON string to the output stream.

## Usage Examples

### Basic Usage (Default Logs: Application and Security)

```powershell
.\Measure-EventLogVolume.ps1
```

**Output Example:**

```
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
```

### Measure Specific Log and Keep History

```powershell
.\Measure-EventLogVolume.ps1 -LogName 'System' -KeepHistory
```

**Output Example (with history):**

```
=== Average Log Volume on MyServer ===

💻 System Log
Oldest Record:  01/01/2023 10:00:00
Newest Record:  05/15/2025 12:00:00
Historical Records:  5
Logs per Hour:  10.50
Logs per Day:   252.00
Logs per Week:  1764.00
Logs per Month: 10920.00
MB per Hour:    0.02
MB per Day:     0.48
MB per Week:    3.36
MB per Month:   20.80
```

### Use History with Custom Path and Filename

```powershell
.\Measure-EventLogVolume.ps1 -KeepHistory -HistoryFilePath 'C:\Temp\LogAnalysis' -TempFileName 'MyEventLogHistory.json'
```

### Write Averages to Output Stream (JSON)

Use the `-WriteAveragesToOutput` switch to get the calculated averages as a JSON string on the output stream. This is useful for piping the results to other cmdlets or for programmatic consumption.

```powershell
.\Measure-EventLogVolume.ps1 -LogName 'Application' -WriteAveragesToOutput
```

**Example Output (JSON to output stream):**

```json
{
    "Application": {
        "LogName": "Application",
        "OldestRecord": "2022-07-19T09:58:14",
        "NewestRecord": "2025-05-14T16:43:08",
        "HistoricalRecords": 1,
        "AverageLogsPerHour": 4.95,
        "AverageMBPerHour": 0.00,
        "AverageLogsPerDay": 118.78,
        "AverageMBPerDay": 0.04,
        "AverageLogsPerWeek": 831.47,
        "AverageMBPerWeek": 0.29,
        "AverageLogsPerMonth": 514.72,
        "AverageMBPerMonth": 0.18
    }
}
```

### Purge Existing History

```powershell
.\Measure-EventLogVolume.ps1 -PurgeHistory
```

This will delete the history file and then run the measurements (for default logs, unless others are specified).
