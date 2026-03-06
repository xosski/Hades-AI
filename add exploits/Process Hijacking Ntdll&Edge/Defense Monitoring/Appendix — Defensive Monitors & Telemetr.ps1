Appendix — Defensive Monitors & Telemetry Plan (added)

Monitored registry surfaces (high-significance, loader‑adjacent)
- IFEO: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*
- Values of interest: Debugger, GlobalFlag, MitigationOptions, UseFilter, VerifierDlls, SilentProcessExit\*, Reporting\*.
- AppInit (Win32 GUI preload): 
- HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows (AppInit_DLLs, LoadAppInit_DLLs, RequireSignedAppInit_DLLs)
- HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows (for 32-bit)
- KnownDLLs (system-wide DLL binding list):
- HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs
- HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs32
- App Paths (ShellExecute resolution for EXEs):
- HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\*.exe
- HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\*.exe

Signals to alert on
- Any modification under KnownDLLs/KnownDLLs32.
- AppInit_DLLs non-empty or LoadAppInit_DLLs enabled (1).
- IFEO subkey creation/changes, especially when Debugger is set.
- App Paths entries pointing to user-writable locations (e.g., %USERPROFILE%, %TEMP%, %PROGRAMDATA%\… non-admin folders).

Controls provided
- Real-time registry watchers (WMI) with on-disk logging and optional Windows Event Log emission.
- Baseline + diff snapshots for the above surfaces.
- Sysmon rules to ensure registry writes are captured (Event IDs 12/13/14) and process starts (ID 1).

Deployment
- Place Monitor-UpdaterHijack.ps1 into a trusted folder; run once to create baseline; register scheduled task for continuous monitoring.
- Merge the Sysmon XML into your environment’s Sysmon policy.

Response guide
- Investigate any unexpected Key/Value changes; validate against admin activity or software updates.
- Revert deviating values to baseline; when IFEO changes are detected with Debugger set, isolate the affected host until root cause is identified.

// ... end of added content ...
<# 
  Monitor-UpdaterHijack.ps1
  Defensive monitor for loader-adjacent registry surfaces (IFEO, AppInit, KnownDLLs, App Paths).
  - Baselines values
  - Real-time WMI registry change watchers (HKLM only; use admin for full coverage)
  - Logs to ProgramData\RegDefense\UpdaterHijack\events.log and optional Windows Event Log

  Usage:
    # Create baseline
    powershell -ExecutionPolicy Bypass -File .\Monitor-UpdaterHijack.ps1 -ReBaseline

    # Run continuous watcher (Ctrl+C to stop)
    powershell -ExecutionPolicy Bypass -File .\Monitor-UpdaterHijack.ps1 -Continuous

    # One-shot check and diff against baseline (no watchers)
    powershell -ExecutionPolicy Bypass -File .\Monitor-UpdaterHijack.ps1

  Notes:
    - WMI registry events: root\default classes RegistryValueChangeEvent / RegistryTreeChangeEvent
    - Requires admin for HKLM subscriptions and writing to Application event log (optional)
#>

[CmdletBinding()]
param(
  [string]$StateDir = "$env:ProgramData\RegDefense\UpdaterHijack",
  [string]$BaselineFile = "$env:ProgramData\RegDefense\UpdaterHijack\baseline.json",
  [switch]$ReBaseline,
  [switch]$Continuous,
  [switch]$EmitEventLog,
  [switch]$IncludeWow6432Node,
  [switch]$IncludeAppModel  # optional, noisy (AppX/AppModel)
)

# Ensure state directory
New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
$LogFile = Join-Path $StateDir 'events.log'

function Write-Log {
  param([string]$Message, [string]$Level = 'INFO')
  $ts = (Get-Date).ToString('s')
  $line = "[$ts][$Level] $Message"
  Add-Content -Path $LogFile -Value $line
  Write-Host $line
  if ($EmitEventLog) {
    $source = 'RegDefense.UpdaterHijack'
    if (-not [System.Diagnostics.EventLog]::SourceExists($source)) {
      try { New-EventLog -LogName Application -Source $source } catch {}
    }
    try { Write-EventLog -LogName Application -Source $source -EntryType Information -EventId 41001 -Message $line } catch {}
  }
}

$Keys = @()

# KnownDLLs (x64 + x86 list)
$Keys += @{ Kind='Tree'; Hive='HKEY_LOCAL_MACHINE'; RootPath='SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs'; Label='KnownDLLs' }
$Keys += @{ Kind='Tree'; Hive='HKEY_LOCAL_MACHINE'; RootPath='SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs32'; Label='KnownDLLs32' }

# AppInit settings (64-bit)
$Keys += @{ Kind='Value'; Hive='HKEY_LOCAL_MACHINE'; KeyPath='SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows'; Values=@('AppInit_DLLs','LoadAppInit_DLLs','RequireSignedAppInit_DLLs'); Label='AppInit64' }
# AppInit settings (Wow6432Node)
$Keys += @{ Kind='Value'; Hive='HKEY_LOCAL_MACHINE'; KeyPath='SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows'; Values=@('AppInit_DLLs','LoadAppInit_DLLs','RequireSignedAppInit_DLLs'); Label='AppInit32'; Optional=(!$IncludeWow6432Node) }

# IFEO subtree (very important, but can be noisy on software installs)
$Keys += @{ Kind='Tree'; Hive='HKEY_LOCAL_MACHINE'; RootPath='SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options'; Label='IFEO' }

# App Paths subtree (watch for user-writable targets)
$Keys += @{ Kind='Tree'; Hive='HKEY_LOCAL_MACHINE'; RootPath='SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths'; Label='AppPaths64' }
$Keys += @{ Kind='Tree'; Hive='HKEY_LOCAL_MACHINE'; RootPath='SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\App Paths'; Label='AppPaths32'; Optional=(!$IncludeWow6432Node) }

# Optional (noisy): AppModel / Appx package repo (for UWP)
if ($IncludeAppModel) {
  $Keys += @{ Kind='Tree'; Hive='HKEY_LOCAL_MACHINE'; RootPath='SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppModel\\PackageRepository\\Packages'; Label='AppModel.PackageRepo'; Optional=$false }
}

function Get-RegValue {
  param([string]$Hive, [string]$Path, [string]$Name)
  $psDrive = switch ($Hive) {
    'HKEY_LOCAL_MACHINE' { 'HKLM:' }
    'HKEY_USERS'         { 'HKU:'  }
    default              { return $null }
  }
  $full = Join-Path $psDrive $Path.Replace('\\','\')
  try {
    if ($Name) {
      $val = (Get-ItemProperty -LiteralPath $full -ErrorAction Stop).$Name
      if ($val -is [byte[]]) { return [Convert]::ToBase64String($val) }
      return "$val"
    } else {
      return (Get-ItemProperty -LiteralPath $full -ErrorAction Stop)
    }
  } catch { return $null }
}

function Get-KeyValues {
  param([string]$Hive, [string]$Path)
  $psDrive = switch ($Hive) {
    'HKEY_LOCAL_MACHINE' { 'HKLM:' }
    'HKEY_USERS'         { 'HKU:'  }
    default              { return @{} }
  }
  $full = Join-Path $psDrive $Path.Replace('\\','\')
  $map = @{}
  try {
    $props = Get-ItemProperty -LiteralPath $full -ErrorAction Stop | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name
    foreach ($p in $props) {
      $v = (Get-ItemProperty -LiteralPath $full).$p
      if ($v -is [byte[]]) { $map[$p] = [Convert]::ToBase64String($v) } else { $map[$p] = "$v" }
    }
  } catch {}
  return $map
}

function Get-Subkeys {
  param([string]$Hive, [string]$Path)
  $psDrive = switch ($Hive) {
    'HKEY_LOCAL_MACHINE' { 'HKLM:' }
    'HKEY_USERS'         { 'HKU:'  }
    default              { return @() }
  }
  $full = Join-Path $psDrive $Path.Replace('\\','\')
  try {
    return (Get-ChildItem -LiteralPath $full -ErrorAction Stop | Select-Object -ExpandProperty PSChildName)
  } catch { return @() }
}

function Build-Baseline {
  $snap = [ordered]@{}
  $snap.Timestamp = (Get-Date).ToUniversalTime().ToString('o')

  # KnownDLLs — capture full value map
  foreach ($k in $Keys | Where-Object { $_.Label -match '^KnownDLLs' -and -not $_.Optional }) {
    $snap[$k.Label] = @{
      Hive = $k.Hive
      Path = $k.RootPath
      Values = Get-KeyValues -Hive $k.Hive -Path $k.RootPath
    }
  }

  # AppInit — capture targeted values
  foreach ($k in $Keys | Where-Object { $_.Label -like 'AppInit*' -and -not $_.Optional }) {
    $vals = @{}
    foreach ($name in $k.Values) {
      $vals[$name] = Get-RegValue -Hive $k.Hive -Path $k.KeyPath -Name $name
    }
    $snap[$k.Label] = @{
      Hive = $k.Hive
      Path = $k.KeyPath
      Values = $vals
    }
  }

  # IFEO — capture subkeys and interesting values
  $ifeo = @{ Hive='HKEY_LOCAL_MACHINE'; Path='SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options'; Entries=@() }
  foreach ($sub in Get-Subkeys -Hive $ifeo.Hive -Path $ifeo.Path) {
    $sPath = "$($ifeo.Path)\\$sub"
    $vals = Get-KeyValues -Hive $ifeo.Hive -Path $sPath
    # Keep only relevant keys for baseline readability
    $sel = @{}
    foreach ($name in @('Debugger','GlobalFlag','MitigationOptions','UseFilter','VerifierDlls','VerifierFlags')) {
      if ($vals.ContainsKey($name)) { $sel[$name] = $vals[$name] }
    }
    # Nested SilentProcessExit/Reporting are common — capture if present
    foreach ($child in @('SilentProcessExit','Reporting')) {
      $cVals = Get-KeyValues -Hive $ifeo.Hive -Path "$sPath\\$child"
      if ($cVals.Count -gt 0) { $sel[$child] = $cVals }
    }
    if ($sel.Count -gt 0) {
      $ifeo.Entries += @{ Image=$sub; Values=$sel }
    }
  }
  $snap.IFEO = $ifeo

  # App Paths — capture executable target and path; flag user-writable targets
  function Is-UserWritablePath([string]$p) {
    if (-not $p) { return $false }
    $p = $p.ToLowerInvariant()
    return ($p -like "$($env:USERPROFILE.ToLowerInvariant())*") -or
           ($p -like "$($env:TEMP.ToLowerInvariant())*") -or
           ($p -like "c:\users\*\*") -or
           ($p -like "c:\programdata\*")
  }
  foreach ($k in $Keys | Where-Object { $_.Label -like 'AppPaths*' -and -not $_.Optional }) {
    $entries = @()
    foreach ($sub in Get-Subkeys -Hive $k.Hive -Path $k.RootPath) {
      $sPath = "$($k.RootPath)\\$sub"
      $vals = Get-KeyValues -Hive $k.Hive -Path $sPath
      $target = $vals[''] # default value holds the executable path
      $pathExt = $vals['Path']
      $entries += @{
        Key = $sub
        Target = $target
        Path = $pathExt
        Suspicious = (Is-UserWritablePath $target)
      }
    }
    $snap[$k.Label] = @{ Hive=$k.Hive; Path=$k.RootPath; Entries=$entries }
  }

  return $snap
}

function Save-Json([object]$obj, [string]$path) {
  $json = $obj | ConvertTo-Json -Depth 10
  Set-Content -Path $path -Value $json -Encoding UTF8
}
function Load-Json([string]$path) {
  if (-not (Test-Path -LiteralPath $path)) { return $null }
  try { return (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json) } catch { return $null }
}

function Flatten-Baseline([pscustomobject]$snap) {
  $flat = @{}
  foreach ($k in @('KnownDLLs','KnownDLLs32')) {
    if ($snap.PSObject.Properties.Name -contains $k) {
      $path = $snap.$k.Path
      foreach ($n in $snap.$k.Values.PSObject.Properties.Name) {
        $flat["$path::$n"] = "$($snap.$k.Values.$n)"
      }
    }
  }
  foreach ($k in @('AppInit64','AppInit32')) {
    if ($snap.PSObject.Properties.Name -contains $k) {
      $path = $snap.$k.Path
      foreach ($n in $snap.$k.Values.PSObject.Properties.Name) {
        $flat["$path::$n"] = "$($snap.$k.Values.$n)"
      }
    }
  }
  if ($snap.PSObject.Properties.Name -contains 'IFEO') {
    foreach ($e in $snap.IFEO.Entries) {
      foreach ($n in $e.Values.PSObject.Properties.Name) {
        $val = $e.Values.$n
        $flat["IFEO::$($e.Image)::$n"] = ( ($val -is [pscustomobject]) ? ($val | ConvertTo-Json -Compress -Depth 5) : "$val" )
      }
    }
  }
  foreach ($k in @('AppPaths64','AppPaths32')) {
    if ($snap.PSObject.Properties.Name -contains $k) {
      foreach ($e in $snap.$k.Entries) {
        $flat["$k::$($e.Key)::Target"] = "$($e.Target)"
        $flat["$k::$($e.Key)::Suspicious"] = "$($e.Suspicious)"
      }
    }
  }
  return $flat
}

function Diff-Maps([hashtable]$old, [hashtable]$new) {
  $changes = @()
  $all = ($old.Keys + $new.Keys) | Select-Object -Unique
  foreach ($k in $all) {
    $ov = $old[$k]; $nv = $new[$k]
    if ($null -eq $ov -and $null -ne $nv) {
      $changes += @{ Key=$k; Change='Added'; New=$nv }
    } elseif ($null -ne $ov -and $null -eq $nv) {
      $changes += @{ Key=$k; Change='Removed'; Old=$ov }
    } elseif ("$ov" -ne "$nv") {
      $changes += @{ Key=$k; Change='Modified'; Old=$ov; New=$nv }
    }
  }
  return $changes
}

function Register-RegistryWatchers {
  $subs = @()
  $ns = 'root\default'
  $i = 0
  foreach ($def in $Keys) {
    if ($def.Optional) { continue }
    if ($def.Kind -eq 'Value') {
      foreach ($vn in $def.Values) {
        $filter = "Hive='{ 0 }' AND KeyPath=' { 1 }' AND ValueName=' { 2 }'" -f $def.Hive, $def.KeyPath, $vn
        $id = "RegWatch-Value-$($def.Label)-$vn"
        try {
          $subs += Register-WmiEvent -Namespace $ns -Class RegistryValueChangeEvent -Filter $filter -SourceIdentifier $id -Action {
            $e = $Event.SourceEventArgs.NewEvent
            $msg = "Registry VALUE change: {0}\{1} [{2}]" -f $e.Hive, $e.KeyPath, $e.ValueName
            Write-Output $msg
          }
          Write-Log "Subscribed: $id ($filter)"
        } catch {
          Write-Log "Failed to subscribe: $id ($filter) :: $($_.Exception.Message)" 'WARN'
        }
      }
    } elseif ($def.Kind -eq 'Tree') {
      $filter = "Hive='{ 0 }' AND RootPath=' { 1 }'" -f $def.Hive, $def.RootPath
      $id = "RegWatch-Tree-$($def.Label)"
      try {
        $subs += Register-WmiEvent -Namespace $ns -Class RegistryTreeChangeEvent -Filter $filter -SourceIdentifier $id -Action {
          $e = $Event.SourceEventArgs.NewEvent
          $msg = "Registry TREE change: {0}\{1}" -f $e.Hive, $e.RootPath
          Write-Output $msg
        }
        Write-Log "Subscribed: $id ($filter)"
      } catch {
        Write-Log "Failed to subscribe: $id ($filter) :: $($_.Exception.Message)" 'WARN'
      }
    }
    $i++
  }
  return $subs
}

# Main flow
if ($ReBaseline) {
  $snap = Build-Baseline
  Save-Json $snap $BaselineFile
  Write-Log "Baseline created at $BaselineFile"
  # Simple heuristics on AppInit and App Paths
  foreach ($k in @('AppInit64','AppInit32')) {
    if ($snap.PSObject.Properties.Name -contains $k) {
      $v = $snap.$k.Values
      if (($v.LoadAppInit_DLLs -as [int]) -eq 1) {
        Write-Log "ALERT: $k LoadAppInit_DLLs is enabled" 'ALERT'
      }
      if ([string]::IsNullOrWhiteSpace($v.AppInit_DLLs) -eq $false) {
        Write-Log "ALERT: $k AppInit_DLLs is non-empty: $($v.AppInit_DLLs)" 'ALERT'
      }
    }
  }
  foreach ($k in @('AppPaths64','AppPaths32')) {
    if ($snap.PSObject.Properties.Name -contains $k) {
      foreach ($e in $snap.$k.Entries) {
        if ($e.Suspicious -eq $true) {
          Write-Log "ALERT: $k $($e.Key) target points to user-writable: $($e.Target)" 'ALERT'
        }
      }
    }
  }
  exit 0
}

# One-shot diff against baseline (if exists)
$baseline = Load-Json $BaselineFile
if ($null -ne $baseline) {
  $current = Build-Baseline
  $flatOld = Flatten-Baseline $baseline
  $flatNew = Flatten-Baseline $current
  $diffs = Diff-Maps $flatOld $flatNew
  if ($diffs.Count -gt 0) {
    foreach ($d in $diffs) {
      $msg = "DIFF: $($d.Change) [$($d.Key)]" + ($(if ($d.Old) { " Old='$($d.Old)'" }) + $(if ($d.New) { " New='$($d.New)'" }))
      Write-Log $msg 'WARN'
    }
  } else {
    Write-Log "No baseline diffs."
  }
} else {
  Write-Log "No baseline found. Run with -ReBaseline to create one." 'WARN'
}

if (-not $Continuous) { return }

Write-Log "Starting continuous watchers..."
$subs = Register-RegistryWatchers

try {
  while ($true) {
    $evt = Wait-Event -Timeout 2
    if ($evt) {
      $txt = $evt.MessageData
      if (-not $txt) {
        # Build message from NewEvent if not provided by action
        $ne = $evt.SourceEventArgs.NewEvent
        if ($ne.CIMClass.CimClassName -eq 'RegistryValueChangeEvent') {
          $txt = "Registry VALUE change: {0}\{1} [{2}]" -f $ne.Hive, $ne.KeyPath, $ne.ValueName
        } else {
          $txt = "Registry TREE change: {0}\{1}" -f $ne.Hive, $ne.RootPath
        }
      }
      Write-Log $txt 'EVENT'
      Remove-Event -EventIdentifier $evt.EventIdentifier | Out-Null
    }
  }
} finally {
  foreach ($s in $subs) { Unregister-Event -SubscriptionId $s.Id -ErrorAction SilentlyContinue }
  Get-Event | Remove-Event -ErrorAction SilentlyContinue
  Write-Log "Watchers stopped."
}
<# Registers a Scheduled Task to run the monitor at logon and every 10 minutes. Run as admin. #>
param(
  [string]$ScriptPath = "C:\ProgramData\RegDefense\UpdaterHijack\Monitor-UpdaterHijack.ps1"
)

# Ensure destination and copy script if needed
$src = "e:\X12\Security-Defenses\monitors\Monitor-UpdaterHijack.ps1"
New-Item -ItemType Directory -Path (Split-Path $ScriptPath) -Force | Out-Null
if (-not (Test-Path -LiteralPath $ScriptPath)) {
  Copy-Item -Path $src -Destination $ScriptPath -Force
}

# Create a baseline if missing
powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -File $ScriptPath -ReBaseline

# Task runs continuous monitoring
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" -Continuous"
$trLogon = New-ScheduledTaskTrigger -AtLogOn
$trOnce  = New-ScheduledTaskTrigger -Once (Get-Date).AddMinutes(1)
$trOnce.Repetition = (New-ScheduledTaskTrigger -Once (Get-Date)).Repetition
$trOnce.Repetition.Interval = "PT10M"

$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
Register-ScheduledTask -TaskName "RegDefense_UpdaterHijack_Monitor" -Action $action -Trigger @($trLogon, $trOnce) -Principal $principal -Force | Out-Null

Write-Host "Scheduled Task 'RegDefense_UpdaterHijack_Monitor' registered."
<!-- Sysmon include rules to capture registry writes to loader-adjacent surfaces and process creation -->
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <!-- Process Create -->
    <ProcessCreate onmatch="include">
      <!-- Capture all; narrow in SIEM if needed -->
      <CommandLine condition="is not"> </CommandLine>
    </ProcessCreate>

    <!-- Registry events: 12 CreateKey, 13 SetValue, 14 RenameKey, 15 CloseKey -->
    <RegistryEvent onmatch="include">
      <!-- IFEO subtree -->
      <TargetObject condition="contains">\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\</TargetObject>

      <!-- AppInit settings (64/32) -->
      <TargetObject condition="contains">\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs</TargetObject>
      <TargetObject condition="contains">\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\LoadAppInit_DLLs</TargetObject>
      <TargetObject condition="contains">\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs</TargetObject>
      <TargetObject condition="contains">\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows\LoadAppInit_DLLs</TargetObject>

      <!-- KnownDLLs (x64/x86) -->
      <TargetObject condition="contains">\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs</TargetObject>
      <TargetObject condition="contains">\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs32</TargetObject>

      <!-- App Paths (x64/x86) -->
      <TargetObject condition="contains">\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\</TargetObject>
      <TargetObject condition="contains">\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\</TargetObject>
    </RegistryEvent>

    <!-- ImageLoad (optional): observe unexpected DLLs loading from user-writable locations -->
    <ImageLoad onmatch="include">
      <ImageLoaded condition="contains">\Users\</ImageLoaded>
      <ImageLoaded condition="contains">\AppData\Local\</ImageLoaded>
      <ImageLoaded condition="contains">\ProgramData\</ImageLoaded>
      <ImageLoaded condition="contains">\Temp\</ImageLoaded>
    </ImageLoad>
  </EventFiltering>
</Sysmon>