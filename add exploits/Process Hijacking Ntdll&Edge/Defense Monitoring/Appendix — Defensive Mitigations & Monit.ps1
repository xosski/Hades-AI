Appendix — Defensive Mitigations & Monitoring (added)

Purpose
- This appendix reframes the concepts above into defensive actions: audit, monitor, alert, and remediate unauthorized changes to the cited registry paths.

Registry paths to audit/monitor
- HKLM\SYSTEM\CurrentControlSet\Services\TSDDD\DEVICE0\Attach.ToDesktop
Note: Some tooling references HKCC\System\CurrentControlSet\Services\TSDDD\DEVICE0; practically, TSDDD lives under HKLM.
- HKU\<SID>\Printers\ConvertUserDevModesCount
- HKU\<SID>\Printers\Defaults\ { GUID }\*
- HKU\<SID>\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run

Detection strategy
- Baseline these values per machine and per user SID.
- On a schedule (e.g., at logon and every 5 minutes), take a new snapshot and diff against baseline.
- Log deviations to ProgramData\RegDefense\events.log and (optionally) to the Windows Event Log for SIEM ingestion.
- Alert on:
- Creation/modification of TSDDD Attach.ToDesktop
- Creation/modification under HKU\<SID>\Printers\Defaults\*
- Changes to StartupApproved\Run entries
- Optional: use Sysmon (Event IDs 12/13/14) to capture registry create/set/rename events on these exact paths.

Deployment
- Place Monitor-RegistryPersistence.ps1 somewhere trusted, e.g., C:\ProgramData\RegDefense\
- Run once as admin to create a baseline.
- Register the scheduled task (Register-DefensiveAuditTask.ps1) to run at logon and every 5 minutes.
- (Optional) Merge the Sysmon config snippet into your environment’s Sysmon policy.

Response
- Investigate any unexpected diffs. Validate against known-good software updates or admin actions.
- If malicious, revert to baseline and disable affected user’s logon until root cause is remediated.
<# 
  Monitor-RegistryPersistence.ps1
  Baselines and detects changes to specific registry paths for defensive monitoring.
  Run elevated for best coverage. PowerShell 5.1+ recommended.
#>

[CmdletBinding()]
param(
    [string]$StateDir = "$env:ProgramData\RegDefense",
    [string]$BaselineFile = "$env:ProgramData\RegDefense\baseline.json",
    [switch]$ReBaseline,
    [switch]$VerboseLog
)

# Ensure state directory exists
New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
$LogFile = Join-Path $StateDir 'events.log'

function Write-Log {
    param([string]$Message)
    $ts = (Get-Date).ToString('s')
    $line = "[$ts] $Message"
    Add-Content -Path $LogFile -Value $line
    if ($VerboseLog) { Write-Host $line }
}

function Get-LoadedUserSids {
    # Enumerate HKEY_USERS for real profiles (S-1-5-21-*)
    $pattern = '^S-1-5-21-\d+-\d+-\d+-\d+$'
    $sids = (Get-ChildItem Registry::HKEY_USERS | Select-Object -ExpandProperty PSChildName) `
    | Where-Object { $_ -match $pattern }
    return $sids
}

function Get-RegistryValueSafe {
    param([string]$Path, [string]$Name = '(default)')
    try {
        $item = Get-Item -LiteralPath $Path -ErrorAction Stop
        $props = Get-ItemProperty -LiteralPath $Path -ErrorAction Stop
        if ($Name -eq '(default)') {
            return $item.GetValue('')
        }
        else {
            return $props.$Name
        }
    }
    catch {
        return $null
    }
}

function Get-RegistryValuesAsMap {
    param([string]$Path)
    $map = @{}
    try {
        $item = Get-Item -LiteralPath $Path -ErrorAction Stop
        $props = Get-ItemProperty -LiteralPath $Path -ErrorAction Stop | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name
        foreach ($p in $props) {
            $val = (Get-ItemProperty -LiteralPath $Path).$p
            if ($val -is [byte[]]) {
                $map[$p] = [System.Convert]::ToBase64String($val)
            }
            else {
                $map[$p] = "$val"
            }
        }
    }
    catch {
        # Path missing is fine
    }
    return $map
}

function Get-SubkeyNames {
    param([string]$Path)
    try {
        return (Get-ChildItem -LiteralPath $Path -ErrorAction Stop | Select-Object -ExpandProperty PSChildName)
    }
    catch {
        return @()
    }
}

function Build-Snapshot {
    $snapshot = [ordered]@{}
    $snapshot.Timestamp = (Get-Date).ToUniversalTime().ToString('o')

    # TSDDD Attach.ToDesktop (under HKLM)
    $tsdddPath = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TSDDD\DEVICE0'
    $snapshot.HKLM_TSDDD = @{
        Path   = $tsdddPath
        Values = Get-RegistryValuesAsMap -Path $tsdddPath
    }

    # Also check HKCC mapping in case tooling uses that alias (defensive)
    $hkccPath = 'Registry::HKEY_CURRENT_CONFIG\System\CurrentControlSet\Services\TSDDD\DEVICE0'
    $snapshot.HKCC_TSDDD = @{
        Path   = $hkccPath
        Values = Get-RegistryValuesAsMap -Path $hkccPath
    }

    # Per-user hives
    $snapshot.HKU = @()
    foreach ($sid in Get-LoadedUserSids) {
        $base = "Registry::HKEY_USERS\$sid"
        $printersBase = "$base\Printers"
        $defaultsBase = "$printersBase\Defaults"
        $startupApproved = "$base\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"

        $entry = [ordered]@{
            SID                = $sid
            Printers           = @{
                ConvertUserDevModesCount = (Get-RegistryValueSafe -Path "$printersBase" -Name 'ConvertUserDevModesCount')
                DefaultsSubkeys          = Get-SubkeyNames -Path $defaultsBase
            }
            StartupApprovedRun = Get-RegistryValuesAsMap -Path $startupApproved
        }
        $snapshot.HKU += $entry
    }

    return $snapshot
}

function Save-Json {
    param([object]$Obj, [string]$Path)
    $json = $Obj | ConvertTo-Json -Depth 8
    Set-Content -Path $Path -Value $json -Encoding UTF8
}

function Load-Json {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try {
        return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    }
    catch {
        return $null
    }
}

function Flatten-Snapshot {
    param([pscustomobject]$Snap)
    $flat = @{}

    # HKLM/HKCC
    foreach ($k in @('HKLM_TSDDD', 'HKCC_TSDDD')) {
        $path = $Snap.$k.Path
        foreach ($name in $Snap.$k.Values.PSObject.Properties.Name) {
            $flat["$path::$name"] = "$($Snap.$k.Values.$name)"
        }
    }

    # HKU entries
    foreach ($u in $Snap.HKU) {
        $sid = $u.SID
        $flat["HKU::$sid::Printers::ConvertUserDevModesCount"] = "$($u.Printers.ConvertUserDevModesCount)"
        $flat["HKU::$sid::Printers::DefaultsSubkeys"] = ($u.Printers.DefaultsSubkeys -join ';')
        foreach ($name in $u.StartupApprovedRun.PSObject.Properties.Name) {
            $flat["HKU::$sid::StartupApproved\Run::$name"] = "$($u.StartupApprovedRun.$name)"
        }
    }

    return $flat
}

function Diff-Flattened {
    param(
        [hashtable]$Old,
        [hashtable]$New
    )
    $changes = @()
    $allKeys = ($Old.Keys + $New.Keys) | Select-Object -Unique
    foreach ($k in $allKeys) {
        $ov = $Old[$k]
        $nv = $New[$k]
        if ($null -eq $ov -and $null -ne $nv) {
            $changes += @{ Key = $k; Change = 'Added'; New = $nv }
        }
        elseif ($null -ne $ov -and $null -eq $nv) {
            $changes += @{ Key = $k; Change = 'Removed'; Old = $ov }
        }
        elseif ("$ov" -ne "$nv") {
            $changes += @{ Key = $k; Change = 'Modified'; Old = $ov; New = $nv }
        }
    }
    return $changes
}

# Main
if ($ReBaseline -or -not (Test-Path -LiteralPath $BaselineFile)) {
    $snap = Build-Snapshot
    Save-Json -Obj $snap -Path $BaselineFile
    Write-Log "Baseline created at $BaselineFile"
    exit 0
}

$baseline = Load-Json -Path $BaselineFile
if ($null -eq $baseline) {
    Write-Log "Baseline missing or unreadable; creating a new baseline."
    $snap = Build-Snapshot
    Save-Json -Obj $snap -Path $BaselineFile
    exit 0
}

$current = Build-Snapshot

$flatOld = Flatten-Snapshot -Snap $baseline
$flatNew = Flatten-Snapshot -Snap $current
$diffs = Diff-Flattened -Old $flatOld -New $flatNew

if ($diffs.Count -gt 0) {
    foreach ($d in $diffs) {
        $msg = "Registry change detected: $($d.Change) [$($d.Key)]" + `
        ($(if ($d.ContainsKey('Old')) { " Old='$($d.Old)'" }) + $(if ($d.ContainsKey('New')) { " New='$($d.New)'" }))
        Write-Log $msg
    }
}
else {
    if ($VerboseLog) { Write-Log "No changes detected." }
}
<!-- Minimal Sysmon include rules for registry paths of interest.
Merge into your existing Sysmon config under EventFiltering. -->
<Sysmon schemaversion="4.90">
<EventFiltering>
<RegistryEvent onmatch="include">
<!-- Event ID 12/13/14 are controlled by this block in current Sysmon schema -->
<TargetObject condition="contains">\SYSTEM\CurrentControlSet\Services\TSDDD\DEVICE0\Attach.ToDesktop</TargetObject>
<TargetObject condition="contains">\Printers\ConvertUserDevModesCount</TargetObject>
<TargetObject condition="contains">\Printers\Defaults\</TargetObject>
<TargetObject condition="contains">\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run</TargetObject>
</RegistryEvent>
</EventFiltering>
</Sysmon>
<# Registers a Scheduled Task to run the monitor at logon and every 5 minutes. Run as admin. #>

param(
    [string]$ScriptPath = "C:\ProgramData\RegDefense\Monitor-RegistryPersistence.ps1"
)

# Ensure script exists at the destination
if (-not (Test-Path -LiteralPath $ScriptPath)) {
    $src = "e:\X12\Security-Defenses\scripts\Monitor-RegistryPersistence.ps1"
    New-Item -ItemType Directory -Path (Split-Path $ScriptPath) -Force | Out-Null
    Copy-Item -Path $src -Destination $ScriptPath -Force
}

$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoLogo -NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""
$trigger1 = New-ScheduledTaskTrigger -AtLogOn
$trigger2 = New-ScheduledTaskTrigger -Once (Get-Date).AddMinutes(1)
$trigger2.Repetition = (New-ScheduledTaskTrigger -Once (Get-Date)).Repetition
$trigger2.Repetition.Interval = "PT5M"  # Every 5 minutes

$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest

Register-ScheduledTask -TaskName "RegDefense_Monitor" -Action $action -Trigger @($trigger1, $trigger2) -Principal $principal -Force | Out-Null

Write-Host "Scheduled Task 'RegDefense_Monitor' registered. Baseline will be created on first run if none exists."