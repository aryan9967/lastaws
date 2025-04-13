<powershell>
$bucket = "malware-analysis-files-aryan-v1"
$key = "{{S3_KEY}}"
$outputLog = "C:\Users\Administrator\sysmon_logs.csv"
$exePath = "C:\Users\Administrator\Desktop\malware.exe"
$maxWait = 300  # seconds
$checkInterval = 10  # seconds

# Download executable
aws s3 cp "s3://$bucket/$key" $exePath

# Start the malware
Start-Process $exePath

# Wait for Sysmon activity (Event ID 1 - Process creation)
$elapsed = 0
$foundEvents = $false

Write-Output "🔍 Monitoring Sysmon for process creation events..."

while ($elapsed -lt $maxWait) {
    $events = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
        Where-Object { $_.Id -eq 1 -and $_.TimeCreated -gt (Get-Date).AddSeconds(-$checkInterval) }

    if ($events.Count -gt 0) {
        Write-Output "✅ Detected Sysmon activity."
        $foundEvents = $true
        break
    }

    Start-Sleep -Seconds $checkInterval
    $elapsed += $checkInterval
}

# Wait a bit more to capture follow-up behavior (optional)
Start-Sleep -Seconds 30

# Export full Sysmon logs to CSV
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
    Export-Csv -Path $outputLog

# Upload to S3
aws s3 cp $outputLog "s3://$bucket/logs/sysmon_logs.csv"

# Shutdown
Stop-Computer -Force
</powershell>
