Appendix — Defensive Monitors & Telemetry Plan (added)

Monitor scope
- Services: HKLM\SYSTEM\CurrentControlSet\Services\edgeupdate, edgeupdatem → ImagePath, executable signature/location/ACLs
- Native Messaging Hosts (Edge/Chrome): HKLM/HKCU\Software\[Microsoft\Edge | Google\Chrome]\NativeMessagingHosts\* → default manifest path; validate JSON + referenced native binary
- Scheduled Tasks: \Microsoft\EdgeUpdate\* → action executable and arguments
- File system: manifest JSON files on disk

Alert conditions
- Service ImagePath not in Program Files\Microsoft\EdgeUpdate or executable not Microsoft-signed
- Native Messaging Host manifest/binary under user-writable directories or manifest JSON malformed
- Any registry change under NativeMessagingHosts trees
- Edge Update Scheduled Task action pointing outside Microsoft EdgeUpdate directories

Deployment
- PowerShell monitor: Monitor-EdgeNativeHostHijack.ps1
- -ReBaseline: create baseline
- -Continuous: start watchers (WMI registry + FileSystemWatcher + scheduled task poller)
- Logs to: %ProgramData%\RegDefense\EdgeHijack\events.log; optional Application event log
- Scheduled Task: Register-EdgeNativeHostTask.ps1
- Sysmon rules: sysmon-edge-nativehost-hijack.xml

Response
- Revert unexpected ImagePath/manifest/task changes to known-good
- Block/ quarantine when non-Microsoft-signed binaries are referenced by services/tasks
- Tighten ACLs on manifest and binary directories if user-write is detected
// Edge Update service ImagePath changes (Sysmon Event 13 if forwarded)
DeviceRegistryEvents
| where RegistryKey endswith @"\SYSTEM\CurrentControlSet\Services\edgeupdate" or RegistryKey endswith @"\SYSTEM\CurrentControlSet\Services\edgeupdatem"
| where RegistryValueName =~ "ImagePath"
| project Timestamp, DeviceName, ActionType, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessAccountDomain, InitiatingProcessAccountName, InitiatingProcessFileName

// Native Messaging Host manifest changes (Sysmon FileCreate/Change)
DeviceFileEvents
| where FolderPath has @"\NativeMessagingHosts\" and FileName endswith ".json"
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine

// msedge spawning native host processes from user-writable locations
DeviceProcessEvents
| where InitiatingProcessFileName =~ "msedge.exe"
| where FolderPath has_any ("\\Users\\", "\\AppData\\Local\\", "\\Temp\\", "\\ProgramData\\")
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessCommandLine
<# 
  Monitor-EdgeNativeHostHijack.ps1
  Defensive monitor for:
    - Edge Update services ImagePath (edgeupdate, edgeupdatem)
    - Native Messaging Host registry keys and manifest JSON files (Edge/Chrome)
    - EdgeUpdate Scheduled Tasks (\Microsoft\EdgeUpdate\*)
  Features:
    - Baseline + diff
    - Real-time WMI registry watchers (services + NMH trees)
    - FileSystemWatcher for manifest files
    - Polling check for Scheduled Tasks every 60s
    - Heuristics: signature check, safe location, user-writable ACLs
#>

[CmdletBinding()]
param(
    [string]$StateDir = "$env:ProgramData\RegDefense\EdgeHijack",
    [string]$BaselineFile = "$env:ProgramData\RegDefense\EdgeHijack\baseline.json",
    [switch]$ReBaseline,
    [switch]$Continuous,
    [switch]$EmitEventLog,
    [int]$TaskPollSeconds = 60
)

# Init
New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
$LogFile = Join-Path $StateDir 'events.log'

$ServiceKeys = @(
    @{ Hive = 'HKEY_LOCAL_MACHINE'; Key = 'SYSTEM\\CurrentControlSet\\Services\\edgeupdate'; Value = 'ImagePath'; Label = 'edgeupdate' },
    @{ Hive = 'HKEY_LOCAL_MACHINE'; Key = 'SYSTEM\\CurrentControlSet\\Services\\edgeupdatem'; Value = 'ImagePath'; Label = 'edgeupdatem' }
)

$NMHRoots = @(
    @{ Hive = 'HKEY_LOCAL_MACHINE'; Root = 'SOFTWARE\\Microsoft\\Edge\\NativeMessagingHosts'; Label = 'Edge.HKLM' },
    @{ Hive = 'HKEY_CURRENT_USER'; Root = 'SOFTWARE\\Microsoft\\Edge\\NativeMessagingHosts'; Label = 'Edge.HKCU' },
    @{ Hive = 'HKEY_LOCAL_MACHINE'; Root = 'SOFTWARE\\Google\\Chrome\\NativeMessagingHosts'; Label = 'Chrome.HKLM' },
    @{ Hive = 'HKEY_CURRENT_USER'; Root = 'SOFTWARE\\Google\\Chrome\\NativeMessagingHosts'; Label = 'Chrome.HKCU' }
)

$ExpectedEdgeUpdateDirs = @(
    (Join-Path ${env:ProgramFiles}     'Microsoft\EdgeUpdate'),
    (Join-Path ${env:ProgramFiles(x86)} 'Microsoft\EdgeUpdate')
) | ForEach-Object { $_.ToLowerInvariant() }

# Logging
function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $ts = (Get-Date).ToString('s')
    $line = "[$ts][$Level] $Message"
    Add-Content -Path $LogFile -Value $line
    Write-Host $line
    if ($EmitEventLog) {
        $source = 'RegDefense.EdgeHijack'
        if (-not [System.Diagnostics.EventLog]::SourceExists($source)) {
            try { New-EventLog -LogName Application -Source $source } catch {}
        }
        try { Write-EventLog -LogName Application -Source $source -EntryType Information -EventId 42001 -Message $line } catch {}
    }
}

# Utils
function Normalize-ExePath([string]$cmd) {
    if ([string]::IsNullOrWhiteSpace($cmd)) { return $null }
    $m = [regex]::Match($cmd, '^\s*(?:"(?<p>[^"]+)"|(?<p>\S+))')
    if ($m.Success) { return $m.Groups['p'].Value }
    return $null
}

function Is-UserWritablePath([string]$path) {
    if ([string]::IsNullOrWhiteSpace($path)) { return $false }
    try {
        $dir = (Test-Path -LiteralPath $path -PathType Container) ? $path : (Split-Path -LiteralPath $path -Parent)
        if (-not (Test-Path -LiteralPath $dir)) { return $false }
        $acl = Get-Acl -LiteralPath $dir
        foreach ($ace in $acl.Access) {
            $id = $ace.IdentityReference.Value.ToLowerInvariant()
            $rights = $ace.FileSystemRights.ToString().ToLowerInvariant()
            if ($ace.AccessControlType -ne 'Allow') { continue }
            if ($id -match 'everyone|authenticated users|users') {
                if ($rights -match 'write|modify|fullcontrol|createfiles|createnew') { return $true }
            }
        }
    }
    catch {}
    $p = $path.ToLowerInvariant()
    return ($p -like "c:\users\*\*") -or ($p -like "$($env:USERPROFILE.ToLowerInvariant())\*") -or ($p -like "c:\programdata\*") -or ($p -like "*\temp\*") -or ($p -like "*\appdata\*")
}

function Get-FileMeta([string]$path) {
    $meta = [ordered]@{ Exists = $false; Path = $path; Hash = ''; SigStatus = ''; Signer = ''; Company = ''; Product = '' }
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $meta }
    $meta.Exists = $true
    try { $meta.Hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash } catch {}
    try { 
        $sig = Get-AuthenticodeSignature -LiteralPath $path
        $meta.SigStatus = "$($sig.Status)"
        $meta.Signer = $sig.SignerCertificate.Subject
    }
    catch {}
    try {
        $fi = Get-Item -LiteralPath $path
        $meta.Company = $fi.VersionInfo.CompanyName
        $meta.Product = $fi.VersionInfo.ProductName
    }
    catch {}
    return $meta
}

function Is-MicrosoftSigned([hashtable]$fileMeta) {
    if (-not $fileMeta.Exists) { return $false }
    if ($fileMeta.SigStatus -notmatch 'Valid') { return $false }
    if ([string]::IsNullOrWhiteSpace($fileMeta.Signer)) { return $false }
    return ($fileMeta.Signer -like '*Microsoft*')
}

# Service validation
function Validate-Service([string]$svcLabel, [string]$cmdline) {
    $exe = Normalize-ExePath $cmdline
    $res = [ordered]@{
        Service = $svcLabel; ImagePath = $cmdline; Exe = $exe; Exists = $false; MicrosoftSigned = $false; UserWritable = $false; SafeLocation = $false
    }
    if ($exe) {
        $meta = Get-FileMeta $exe
        $res.Exists = $meta.Exists
        $res.MicrosoftSigned = Is-MicrosoftSigned $meta
        $res.UserWritable = Is-UserWritablePath $exe
        $res.SafeLocation = ($ExpectedEdgeUpdateDirs | ForEach-Object { ($exe.ToLowerInvariant()).StartsWith($_) } | Where-Object { $_ } | Select-Object -First 1) -ne $null
    }
    return $res
}

# NMH enumeration/validation
function Enumerate-NMHManifests {
    $list = @()
    foreach ($root in $NMHRoots) {
        $psDrive = ($root.Hive -eq 'HKEY_LOCAL_MACHINE') ? 'HKLM:' : 'HKCU:'
        $base = Join-Path $psDrive $root.Root.Replace('\\', '\')
        try { $subs = Get-ChildItem -LiteralPath $base -ErrorAction Stop } catch { $subs = @() }
        foreach ($s in $subs) {
            $manifest = (Get-Item -LiteralPath $s.PSPath).GetValue('')
            if ([string]::IsNullOrWhiteSpace($manifest)) { continue }
            $list += [pscustomobject]@{ Hive = $root.Hive; Root = $root.Root; Host = $s.PSChildName; Manifest = $manifest }
        }
    }
    return $list
}

function Read-Manifest([string]$path) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
    try { return (Get-Content -LiteralPath $path -Raw -Encoding UTF8) | ConvertFrom-Json -ErrorAction Stop } catch { return $null }
}

function Validate-Manifest([string]$manifestPath) {
    $res = [ordered]@{
        Manifest = $manifestPath; Exists = $false; JsonValid = $false; NativePath = ''; NativeExists = $false; NativeMicrosoftSigned = $false; NativeUserWritable = $false; ManifestUserWritable = $false
    }
    $res.ManifestUserWritable = Is-UserWritablePath $manifestPath
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { return $res }
    $res.Exists = $true
    $json = Read-Manifest $manifestPath
    if ($null -ne $json) {
        $res.JsonValid = $true
        $res.NativePath = $json.path
        if ($res.NativePath) {
            $meta = Get-FileMeta $res.NativePath
            $res.NativeExists = $meta.Exists
            $res.NativeMicrosoftSigned = Is-MicrosoftSigned $meta
            $res.NativeUserWritable = Is-UserWritablePath $res.NativePath
        }
    }
    return $res
}

# Scheduled Tasks (EdgeUpdate)
function Enumerate-EdgeTasks {
    try {
        $tasks = Get-ScheduledTask -TaskPath '\Microsoft\EdgeUpdate\' -ErrorAction Stop
    }
    catch { $tasks = @() }
    $entries = @()
    foreach ($t in $tasks) {
        $actions = @()
        foreach ($a in $t.Actions) {
            $exe = $a.Execute
            $args = $a.Arguments
            $full = if ($exe -and (Test-Path $exe)) { $exe } else { $exe }
            $actions += @{
                Execute      = $exe
                Arguments    = $args
                SafeLocation = ($ExpectedEdgeUpdateDirs | ForEach-Object { ($exe.ToLowerInvariant()).StartsWith($_) } | Where-Object { $_ } | Select-Object -First 1) -ne $null
                UserWritable = Is-UserWritablePath $exe
            }
        }
        $entries += @{
            TaskName = $t.TaskName
            Path     = $t.TaskPath
            Actions  = $actions
            Triggers = ($t.Triggers | ForEach-Object { $_.ToString() })
            State    = (Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath).State
        }
    }
    return $entries
}

# Baseline builders
function Build-Baseline {
    $snap = [ordered]@{}
    $snap.Timestamp = (Get-Date).ToUniversalTime().ToString('o')

    # Services
    $svc = @()
    foreach ($sk in $ServiceKeys) {
        $cmd = (Get-ItemProperty -LiteralPath ("HKLM:\\" + $sk.Key.Replace('\\', '\')) -ErrorAction SilentlyContinue).$($sk.Value)
        $svc += (Validate-Service $sk.Label $cmd)
    }
    $snap.Services = $svc

    # NMH
    $nmh = @()
    foreach ($m in Enumerate-NMHManifests) {
        $nmh += @{
            Hive = $m.Hive; Root = $m.Root; Host = $m.Host; Manifest = (Validate-Manifest $m.Manifest)
        }
    }
    $snap.NMH = $nmh

    # EdgeUpdate Scheduled Tasks
    $snap.EdgeTasks = (Enumerate-EdgeTasks)
    return $snap
}

function Save-Json([object]$obj, [string]$path) {
    Set-Content -Path $path -Value ($obj | ConvertTo-Json -Depth 12) -Encoding UTF8
}
function Load-Json([string]$path) {
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    try { return (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json) } catch { return $null }
}

# Flatten + diff
function Flatten([pscustomobject]$snap) {
    $flat = @{}
    foreach ($s in $snap.Services) {
        foreach ($n in $s.PSObject.Properties.Name) { $flat["Service::$($s.Service)::$n"] = "$($s.$n)" }
    }
    foreach ($e in $snap.NMH) {
        $m = $e.Manifest
        $prefix = "NMH::$($e.Hive)\$($e.Root)::Host=$($e.Host)"
        foreach ($n in $m.PSObject.Properties.Name) {
            $val = $m.$n
            $flat["$prefix::$n"] = ($val -is [pscustomobject]) ? ($val | ConvertTo-Json -Compress -Depth 5) : "$val"
        }
    }
    $i = 0
    foreach ($t in $snap.EdgeTasks) {
        $flat["Task::$($t.Path)$($t.TaskName)::State"] = "$($t.State)"
        $aIdx = 0
        foreach ($a in $t.Actions) {
            $flat["Task::$($t.Path)$($t.TaskName)::Action[$aIdx].Execute"] = "$($a.Execute)"
            $flat["Task::$($t.Path)$($t.TaskName)::Action[$aIdx].SafeLocation"] = "$($a.SafeLocation)"
            $flat["Task::$($t.Path)$($t.TaskName)::Action[$aIdx].UserWritable"] = "$($a.UserWritable)"
            $aIdx++
        }
        $i++
    }
    return $flat
}
function Diff-Maps([hashtable]$old, [hashtable]$new) {
    $changes = @()
    $all = ($old.Keys + $new.Keys) | Select-Object -Unique
    foreach ($k in $all) {
        $ov = $old[$k]; $nv = $new[$k]
        if ($null -eq $ov -and $null -ne $nv) {
            $changes += @{ Key = $k; Change = 'Added'; New = $nv } 
        }
        elseif ($null -ne $ov -and $null -eq $nv) {
            $changes += @{ Key = $k; Change = 'Removed'; Old = $ov } 
        }
        elseif ("$ov" -ne "$nv") {
            $changes += @{ Key = $k; Change = 'Modified'; Old = $ov; New = $nv } 
        }
        return $changes
    }

    # Watchers
    $RegSubs = @()
    $FSWatchers = @()

    function Start-ManifestWatcher([string]$manifestPath) {
        if ([string]::IsNullOrWhiteSpace($manifestPath)) { return }
        $dir = Split-Path -LiteralPath $manifestPath -Parent
        if (-not (Test-Path -LiteralPath $dir)) { return }
        if ($Global:WatchedDirs -and $Global:WatchedDirs.Contains($dir)) { return }

        $fsw = New-Object System.IO.FileSystemWatcher($dir, '*.json')
        $fsw.IncludeSubdirectories = $false
        $fsw.EnableRaisingEvents = $true
        $Global:WatchedDirs = $Global:WatchedDirs ?? New-Object System.Collections.Generic.HashSet[string]
        [void]$Global:WatchedDirs.Add($dir)

        $handler = {
            param($sender, $eventArgs)
            $path = $eventArgs.FullPath
            $act = $eventArgs.ChangeType
            $res = Validate-Manifest $path
            $sev = 'EVENT'
            if ($res.ManifestUserWritable -or $res.NativeUserWritable -or (-not $res.JsonValid) -or (-not $res.NativeExists)) { $sev = 'ALERT' }
            Write-Log ("Manifest $act: $path; JsonValid=$($res.JsonValid); Native=$($res.NativePath); NativeExists=$($res.NativeExists); NativeWritable=$($res.NativeUserWritable); ManifestWritable=$($res.ManifestUserWritable)") $sev
        }

        Register-ObjectEvent -InputObject $fsw -EventName Changed -SourceIdentifier "FSW-$dir-Changed" -Action $handler | Out-Null
        Register-ObjectEvent -InputObject $fsw -EventName Created -SourceIdentifier "FSW-$dir-Created" -Action $handler | Out-Null
        Register-ObjectEvent -InputObject $fsw -EventName Renamed -SourceIdentifier "FSW-$dir-Renamed" -Action $handler | Out-Null
        Register-ObjectEvent -InputObject $fsw -EventName Deleted -SourceIdentifier "FSW-$dir-Deleted" -Action {
            param($sender, $eventArgs)
            Write-Log ("Manifest Deleted: {0}" -f $eventArgs.FullPath) 'EVENT'
        } | Out-Null

        $FSWatchers += $fsw
        Write-Log "Watching manifest directory: $dir"
    }

    function Register-RegistryWatchers {
        $ns = 'root\default'
        # Service ImagePath watchers
        foreach ($s in $ServiceKeys) {
            $filter = "Hive='{0}' AND KeyPath='{1}' AND ValueName='{2}'" -f $s.Hive, $s.Key, $s.Value
            $id = "RegWatch-Service-$($s.Label)"
            try {
                $RegSubs += Register-WmiEvent -Namespace $ns -Class RegistryValueChangeEvent -Filter $filter -SourceIdentifier $id -Action {
                    $svcLabel = $using:s.Label
                    $cmd = (Get-ItemProperty -LiteralPath ("HKLM:\\" + $using:s.Key.Replace('\\', '\')) -ErrorAction SilentlyContinue).$($using:s.Value)
                    $check = Validate-Service $svcLabel $cmd
                    $sev = 'EVENT'
                    if (-not $check.MicrosoftSigned -or -not $check.SafeLocation -or $check.UserWritable -or -not $check.Exists) { $sev = 'ALERT' }
                    Write-Log ("Service ImagePath change [{0}]: {1} (Exe={2} Exists={3} MSFTSigned={4} SafeLoc={5} UserWritable={6})" -f $svcLabel, $cmd, $check.Exe, $check.Exists, $check.MicrosoftSigned, $check.SafeLocation, $check.UserWritable) $sev
                }
                Write-Log "Subscribed: $id ($filter)"
            }
            catch {
                Write-Log "Failed to subscribe: $id ($filter) :: $($_.Exception.Message)" 'WARN'
            }
        }

        # NMH tree watchers
        foreach ($r in $NMHRoots) {
            $filter = "Hive='{0}' AND RootPath='{1}'" -f $r.Hive, $r.Root
            $id = "RegWatch-NMH-$($r.Label)"
            try {
                $RegSubs += Register-WmiEvent -Namespace $ns -Class RegistryTreeChangeEvent -Filter $filter -SourceIdentifier $id -Action {
                    $evt = $Event.SourceEventArgs.NewEvent
                    Write-Log ("NMH registry change: {0}\{1}" -f $evt.Hive, $evt.RootPath) 'EVENT'
                    foreach ($m in Enumerate-NMHManifests) { Start-ManifestWatcher $m.Manifest }
                }
                Write-Log "Subscribed: $id ($filter)"
            }
            catch {
                Write-Log "Failed to subscribe: $id ($filter) :: $($_.Exception.Message)" 'WARN'
            }
        }
    }

    # Main
    if ($ReBaseline) {
        $snap = Build-Baseline
        Save-Json $snap $BaselineFile
        Write-Log "Baseline created at $BaselineFile"

        # Emit heuristics
        foreach ($s in $snap.Services) {
            if (-not $s.Exists -or -not $s.MicrosoftSigned -or -not $s.SafeLocation -or $s.UserWritable) {
                Write-Log ("ALERT: Service {0} ImagePath suspicious. Exists={1} MSFTSigned={2} SafeLoc={3} UserWritable={4} ImagePath={5}" -f $s.Service, $s.Exists, $s.MicrosoftSigned, $s.SafeLocation, $s.UserWritable, $s.ImagePath) 'ALERT'
            }
        }
        foreach ($n in $snap.NMH) {
            $m = $n.Manifest
            if (-not $m.JsonValid -or $m.ManifestUserWritable -or $m.NativeUserWritable -or -not $m.NativeExists) {
                Write-Log ("ALERT: NMH {0} ({1}) manifest/native issues. Manifest={2} Native={3} JsonValid={4} ManWritable={5} NativeWritable={6} NativeExists={7}" -f $n.Host, $n.Hive, $m.Manifest, $m.NativePath, $m.JsonValid, $m.ManifestUserWritable, $m.NativeUserWritable, $m.NativeExists) 'ALERT'
            }
        }
        foreach ($t in $snap.EdgeTasks) {
            foreach ($a in $t.Actions) {
                if (-not $a.SafeLocation -or $a.UserWritable) {
                    Write-Log ("ALERT: EdgeUpdate task {0}{1} action points to unsafe path: {2} (UserWritable={3})" -f $t.Path, $t.TaskName, $a.Execute, $a.UserWritable) 'ALERT'
                }
            }
        }

        # Prime manifest watchers
        foreach ($m in Enumerate-NMHManifests) { Start-ManifestWatcher $m.Manifest }
        exit 0
    }

    # One-shot diff
    $baseline = Load-Json $BaselineFile
    if ($null -ne $baseline) {
        $current = Build-Baseline
        $diff = Diff-Maps (Flatten $baseline) (Flatten $current)
        if ($diff.Count -gt 0) {
            foreach ($d in $diff) {
                $msg = "DIFF: $($d.Change) [$($d.Key)]" + ($(if ($d.Old) { " Old='$($d.Old)'" }) + $(if ($d.New) { " New='$($d.New)'" }))
                Write-Log $msg 'WARN'
            }
        }
        else {
            Write-Log "No baseline diffs."
        }
    }
    else {
        Write-Log "No baseline found. Run with -ReBaseline to create one." 'WARN'
    }

    if (-not $Continuous) { return }

    # Continuous watchers and pollers
    Write-Log "Starting continuous registry + manifest watchers + scheduled task poller..."
    Register-RegistryWatchers
    foreach ($m in Enumerate-NMHManifests) { Start-ManifestWatcher $m.Manifest }

    $lastTaskSnapshot = (Enumerate-EdgeTasks) | ConvertTo-Json -Depth 10

    try {
        while ($true) {
            # Drain event queue (Registry and FSW)
            $evt = Wait-Event -Timeout 2
            if ($evt) {
                Remove-Event -EventIdentifier $evt.EventIdentifier | Out-Null
            }

            # Poll scheduled tasks
            $now = Get-Date
            if (-not $global:__lastTaskPoll -or ($now - $global:__lastTaskPoll).TotalSeconds -ge $TaskPollSeconds) {
                $global:__lastTaskPoll = $now
                $curr = (Enumerate-EdgeTasks) | ConvertTo-Json -Depth 10
                if ($curr -ne $lastTaskSnapshot) {
                    Write-Log "EdgeUpdate Scheduled Tasks changed." 'EVENT'
                    # Simple re-validate
                    $currObjs = $curr | ConvertFrom-Json
                    foreach ($t in $currObjs) {
                        foreach ($a in $t.Actions) {
                            if (-not $a.SafeLocation -or $a.UserWritable) {
                                Write-Log ("ALERT: EdgeUpdate task {0}{1} action points to unsafe path: {2} (UserWritable={3})" -f $t.Path, $t.TaskName, $a.Execute, $a.UserWritable) 'ALERT'
                            }
                        }
                    }
                    $lastTaskSnapshot = $curr
                }
            }
        }
    }
    finally {
        foreach ($s in $RegSubs) { Unregister-Event -SubscriptionId $s.Id -ErrorAction SilentlyContinue }
        Get-Event | Remove-Event -ErrorAction SilentlyContinue
        foreach ($w in $FSWatchers) { $w.EnableRaisingEvents = $false; $w.Dispose() }
        Write-Log "Watchers stopped."
    }
    <!-- Sysmon include rules for Edge Update service hijack and Native Messaging Hosts -->
    <Sysmon schemaversion="4.90">
    <EventFiltering>
    <!-- ProcessCreate: capture MicrosoftEdgeUpdate.exe and msedge-initiated native hosts -->
    <ProcessCreate onmatch="include">
    <Image condition="contains">\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe</Image>
    <ParentImage condition="contains">\msedge.exe</ParentImage>
    </ProcessCreate>

    <!-- Registry: Services ImagePath and NativeMessagingHosts -->
    <RegistryEvent onmatch="include">
    <TargetObject condition="end with">\SYSTEM\CurrentControlSet\Services\edgeupdate\ImagePath</TargetObject>
    <TargetObject condition="end with">\SYSTEM\CurrentControlSet\Services\edgeupdatem\ImagePath</TargetObject>
    <TargetObject condition="contains">\SOFTWARE\Microsoft\Edge\NativeMessagingHosts\</TargetObject>
    <TargetObject condition="contains">\SOFTWARE\Google\Chrome\NativeMessagingHosts\</TargetObject>
    </RegistryEvent>

    <!-- File events: manifest JSONs -->
    <FileCreate onmatch="include">
    <TargetFilename condition="contains">\NativeMessagingHosts\</TargetFilename>
    <TargetFilename condition="end with">.json</TargetFilename>
    </FileCreate>
    <FileCreateStreamHash onmatch="include">
    <TargetFilename condition="contains">\NativeMessagingHosts\</TargetFilename>
    <TargetFilename condition="end with">.json</TargetFilename>
    </FileCreateStreamHash>
    <FileCreateTime onmatch="include">
    <TargetFilename condition="contains">\NativeMessagingHosts\</TargetFilename>
    <TargetFilename condition="end with">.json</TargetFilename>
    </FileCreateTime>
    </EventFiltering>
    </Sysmon>