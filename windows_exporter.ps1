# =========================================================
# SECURITY LOG ANALYZER
# Windows Authentication Exporter - V8
# =========================================================

$OutputFile = ".\windows_auth.csv"

Write-Host "==============================================="
Write-Host " SECURITY LOG ANALYZER - WINDOWS EXPORTER V8"
Write-Host "==============================================="
Write-Host ""
Write-Host "Reading Windows authentication events..."
Write-Host ""

# ---------------------------------------------------------
# COLLECT SUCCESSFUL LOGONS - 4624
# ---------------------------------------------------------

$successEvents = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id      = 4624
} -MaxEvents 100 -ErrorAction SilentlyContinue

# ---------------------------------------------------------
# COLLECT FAILED LOGONS - 4625
# ---------------------------------------------------------

$failedEvents = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id      = 4625
} -MaxEvents 100 -ErrorAction SilentlyContinue

# ---------------------------------------------------------
# COMBINE EVENTS
# ---------------------------------------------------------

$events = @()

if ($successEvents) {
    $events += $successEvents
}

if ($failedEvents) {
    $events += $failedEvents
}

# ---------------------------------------------------------
# PROCESS EVENTS
# ---------------------------------------------------------

$results = foreach ($event in $events) {

    $xml = [xml]$event.ToXml()
    $data = @{}

    foreach ($item in $xml.Event.EventData.Data) {

        if ($item.Name) {
            $data[$item.Name] = $item.'#text'
        }
    }

    $username = $data['TargetUserName']
    $sourceIP = $data['IpAddress']
    $logonType = $data['LogonType']

    # Ignore common Windows-generated accounts
    if (
        $username -eq 'SYSTEM' -or
        $username -eq 'LOCAL SERVICE' -or
        $username -eq 'NETWORK SERVICE' -or
        $username -like 'DWM-*' -or
        $username -like 'UMFD-*'
    ) {
        continue
    }

    # Keep useful authentication logon types
    if (
        $logonType -notin @(
            '2',
            '3',
            '7',
            '10',
            '11'
        )
    ) {
        continue
    }

    # Replace missing source addresses
    if (
        [string]::IsNullOrWhiteSpace($sourceIP) -or
        $sourceIP -eq '-'
    ) {
        $sourceIP = 'LOCAL'
    }

    [PSCustomObject]@{
        TimeCreated = $event.TimeCreated
        EventID     = $event.Id
        RecordID    = $event.RecordId
        Username    = $username
        SourceIP    = $sourceIP
        LogonType   = $logonType
    }
}

# ---------------------------------------------------------
# EXPORT CSV
# ---------------------------------------------------------

$results |
    Sort-Object TimeCreated |
    Export-Csv `
        -Path $OutputFile `
        -NoTypeInformation

# ---------------------------------------------------------
# SUMMARY
# ---------------------------------------------------------

$successCount = @(
    $results |
    Where-Object {
        $_.EventID -eq 4624
    }
).Count

$failureCount = @(
    $results |
    Where-Object {
        $_.EventID -eq 4625
    }
).Count

Write-Host "Export complete."
Write-Host ""

Write-Host "Successful logons:" $successCount
Write-Host "Failed logons:" $failureCount
Write-Host "Total relevant events:" @($results).Count

Write-Host ""
Write-Host "Output:" $OutputFile