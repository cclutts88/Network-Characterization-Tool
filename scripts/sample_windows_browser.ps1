param(
    [Parameter(Mandatory=$true)][string]$ProfileRoot,
    [Parameter(Mandatory=$true)][string]$StopFile,
    [Parameter(Mandatory=$true)][string]$OutputFile
)
$peakWorkingSet = [int64]0
$maximumCpuTicks = @{}
$processes = @{}
$seen = New-Object 'System.Collections.Generic.HashSet[int]'
$sampleCount = 0
while (-not (Test-Path -LiteralPath $StopFile)) {
    $aggregate = [int64]0
    $rows = Get-CimInstance Win32_Process -Filter "Name='chrome.exe'" |
        Where-Object { $_.CommandLine -and $_.CommandLine.Contains($ProfileRoot) }
    foreach ($row in $rows) {
        [void]$seen.Add([int]$row.ProcessId)
        if (-not $processes.ContainsKey([int]$row.ProcessId)) {
            $processes[[int]$row.ProcessId] = [ordered]@{
                process_id = [int]$row.ProcessId
                parent_process_id = [int]$row.ParentProcessId
                creation_date = [string]$row.CreationDate
                executable_path = [string]$row.ExecutablePath
            }
        }
        $aggregate += [int64]$row.WorkingSetSize
        $ticks = [int64]$row.KernelModeTime + [int64]$row.UserModeTime
        if (-not $maximumCpuTicks.ContainsKey($row.ProcessId) -or $ticks -gt $maximumCpuTicks[$row.ProcessId]) {
            $maximumCpuTicks[$row.ProcessId] = $ticks
        }
    }
    if ($aggregate -gt $peakWorkingSet) { $peakWorkingSet = $aggregate }
    $sampleCount += 1
    Start-Sleep -Milliseconds 100
}
$cpuTicks = [int64]0
foreach ($value in $maximumCpuTicks.Values) { $cpuTicks += [int64]$value }
$result = [ordered]@{
    method = 'Win32_Process profile-root sampling at 100 ms'
    profile_root = $ProfileRoot
    process_ids = @($seen | Sort-Object)
    processes = @($processes.Values | Sort-Object process_id)
    process_count = $seen.Count
    sample_count = $sampleCount
    peak_working_set_bytes = $peakWorkingSet
    cpu_seconds = [math]::Round($cpuTicks / 10000000.0, 6)
}
$result | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $OutputFile -Encoding utf8
