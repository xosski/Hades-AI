Appendix — Defensive Monitors & Telemetry Plan (added)

Monitored surfaces
- Services (HKLM\SYSTEM\CurrentControlSet\Services):
- edgeupdate\ImagePath
- edgeupdatem\ImagePath
- Validate executable path, signature, location, and directory ACLs
- Native Messaging Hosts (Edge/Chrome):
- HKLM\SOFTWARE\Microsoft\Edge\NativeMessagingHosts\*
- HKCU\SOFTWARE\Microsoft\Edge\NativeMessagingHosts\*
- HKLM\SOFTWARE\Google\Chrome\NativeMessagingHosts\*
- HKCU\SOFTWARE\Google\Chrome\NativeMessagingHosts\*
- Validate manifest JSON and the "path" to the native binary
- Watch the manifest files on disk for changes

Alerts
- Service ImagePath not under Program Files (Microsoft\EdgeUpdate) or executable not Microsoft-signed
- Manifest path or native binary under user-writable locations (Users, AppData, Temp, ProgramData with weak ACLs)
- Manifest JSON changes or registry changes to NativeMessagingHosts keys
- Edge Update service ImagePath modification

Deployment
- Baseline and diff: Monitor-EdgeNativeHostHijack.ps1
- Continuous watchers (WMI + FileSystemWatcher)
- Optional: Scheduled Task registration script
- Sysmon snippet for registry/files/process coverage

Response
- Validate changes against approved updates; if unexpected, revert ImagePath and manifest paths to known-good state
- Quarantine hosts if service ImagePath is modified to non-Microsoft-signed executables
- Tighten directory ACLs where user write access is detected
<# 
  Monitor-EdgeNativeHostHijack.ps1
  Defensive monitor for:
    - Edge Update services ImagePath (edgeupdate, edgeupdatem)
    - Native Messaging Hosts (Edge/Chrome) registry and manifest JSON files
  Features:
    - Baseline + diff
    - Real-time WMI registry watchers for services and NativeMessagingHosts
    - FileSystemWatcher for manifest JSON files
    - Heuristics: signature check, safe location, user-writable ACLs, suspicious args
  Usage:
    # Create baseline
    powershell -ExecutionPolicy Bypass -File .\Monitor-EdgeNativeHostHijack.ps1 -ReBaseline

    # One-shot diff
    powershell -ExecutionPolicy Bypass -File .\Monitor-EdgeNativeHostHijack.ps1

    # Continuous monitoring (Ctrl+C to stop)
    powershell -ExecutionPolicy Bypass -File .\Monitor-EdgeNativeHostHijack.ps1 -Continuous -EmitEventLog
#>

[CmdletBinding()]
param(
    [string]$StateDir = "$env:ProgramData\RegDefense\EdgeHijack",
    [string]$BaselineFile = "$env:ProgramData\RegDefense\EdgeHijack\baseline.json",
    [switch]$ReBaseline,
    [switch]$Continuous,
    [switch]$EmitEventLog
)

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

# Utilities
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
                if ($rights -match 'write|modify|fullcontrol|createnew|createfiles') { return $true }
            }
        }
    }
    catch {}
    # Heuristic fallback
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
        $meta.Company = ($fi.VersionInfo.CompanyName)
        $meta.Product = ($fi.VersionInfo.ProductName)
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

function Validate-Service([string]$svcLabel, [string]$cmdline) {
    $exe = Normalize-ExePath $cmdline
    $res = [ordered]@{
        Service = $svcLabel; ImagePath = $cmdline; Exe = $exe; Exists = $false; MicrosoftSigned = $false; UserWritable = $false; SafeLocation = $false; SuspiciousArgs = $false
    }
    if ($exe) {
        $meta = Get-FileMeta $exe
        $res.Exists = $meta.Exists
        $res.MicrosoftSigned = Is-MicrosoftSigned $meta
        $res.UserWritable = Is-UserWritablePath $exe

        $safeDirs = @(
            (Join-Path ${env:ProgramFiles(x86)} 'Microsoft\EdgeUpdate'),
            (Join-Path ${env:ProgramFiles}     'Microsoft\EdgeUpdate')
        ) | ForEach-Object { $_.ToLowerInvariant() }
        $res.SafeLocation = $safeDirs | ForEach-Object { ($exe.ToLowerInvariant()).StartsWith($_) } | Where-Object { $_ } | ForEach-Object { $true } | Select-Object -First 1
        if (-not $res.SafeLocation) { $res.SafeLocation = $false }

        # Suspicious args: ImagePath without "/svc" or with unusual extra args
        $res.SuspiciousArgs = ($cmdline -notmatch '/(svc|medsvc)\b')
    }
    return $res
}

function Get-RegistryDefault([string]$hive, [string]$keyPath) {
    $psDrive = switch ($hive) {
        'HKEY_LOCAL_MACHINE' { 'HKLM:' }
        'HKEY_CURRENT_USER' { 'HKCU:' }
        default { return $null }
    }
    $full = Join-Path $psDrive $keyPath.Replace('\\', '\')
    try {
        $k = Get-Item -LiteralPath $full -ErrorAction Stop
        return $k.GetValue('')
    }
    catch { return $null }
}

function Enumerate-NMHManifests {
    $list = @()
    foreach ($root in $NMHRoots) {
        $psDrive = ($root.Hive -eq 'HKEY_LOCAL_MACHINE') ? 'HKLM:' : 'HKCU:'
        $base = Join-Path $psDrive $root.Root.Replace('\\', '\')
        try {
            $subs = Get-ChildItem -LiteralPath $base -ErrorAction Stop
        }
        catch { $subs = @() }
        foreach ($s in $subs) {
            $manifest = (Get-Item -LiteralPath $s.PSPath).GetValue('')
            if ([string]::IsNullOrWhiteSpace($manifest)) { continue }
            $hostName = $s.PSChildName
            $list += [pscustomobject]@{
                Hive = $root.Hive; Root = $root.Root; Host = $hostName; Manifest = $manifest
            }
        }
    }
    return $list
}

function Read-Manifest([string]$path) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
    try {
        $raw = Get-Content -LiteralPath $path -Raw -Encoding UTF8
        return $raw | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        return $null
    }
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
        if (-not [string]::IsNullOrWhiteSpace($res.NativePath)) {
            $meta = Get-FileMeta $res.NativePath
            $res.NativeExists = $meta.Exists
            $res.NativeMicrosoftSigned = Is-MicrosoftSigned $meta
            $res.NativeUserWritable = Is-UserWritablePath $res.NativePath
        }
    }
    return $res
}

function Build-Baseline {
    $snap = [ordered]@{}
    $snap.Timestamp = (Get-Date).ToUniversalTime().ToString('o')

    # Services
    $svc = @()
    foreach ($sk in $ServiceKeys) {
        $cmd = (Get-ItemProperty -LiteralPath ("HKLM:\\" + $sk.Key.Replace('\\', '\')) -ErrorAction SilentlyContinue).$($sk.Value)
        $val = Validate-Service $sk.Label $cmd
        $svc += $val
    }
    $snap.Services = $svc

    # Native Messaging Hosts
    $nmh = @()
    $manifests = Enumerate-NMHManifests
    foreach ($m in $manifests) {
        $check = Validate-Manifest $m.Manifest
        $nmh += @{
            Hive = $m.Hive; Root = $m.Root; Host = $m.Host; Manifest = $check
        }
    }
    $snap.NMH = $nmh
    return $snap
}

function Save-Json([object]$obj, [string]$path) {
    Set-Content -Path $path -Value ($obj | ConvertTo-Json -Depth 10) -Encoding UTF8
}
function Load-Json([string]$path) {
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    try { return (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json) } catch { return $null }
}

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
            if ($val -is [pscustomobject]) {
                foreach ($n2 in $val.PSObject.Properties.Name) {
                    $flat["$prefix::Manifest.$n2"] = "$($val.$n2)"
                }
            }
            else {
                $flat["$prefix::Manifest.$n"] = "$val"
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

    # Continuous watchers
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
            $msg = "Manifest $act: $path; Exists=$($res.Exists); JsonValid=$($res.JsonValid); Native=$($res.NativePath); NativeExists=$($res.NativeExists); NativeWritable=$($res.NativeUserWritable); ManifestWritable=$($res.ManifestUserWritable)"
            if ($res.ManifestUserWritable -or ($res.NativeUserWritable) -or (-not $res.JsonValid) -or (-not $res.NativeExists)) { $sev = 'ALERT' }
            Write-Log $msg $sev
        }

        Register-ObjectEvent -InputObject $fsw -EventName Changed -SourceIdentifier "FSW-$dir-Changed" -Action $handler | Out-Null
        Register-ObjectEvent -InputObject $fsw -EventName Created -SourceIdentifier "FSW-$dir-Created" -Action $handler | Out-Null
        Register-ObjectEvent -InputObject $fsw -EventName Renamed -SourceIdentifier "FSW-$dir-Renamed" -Action $handler | Out-Null
        Register-ObjectEvent -InputObject $fsw -EventName Deleted -SourceIdentifier "FSW-$dir-Deleted" -Action {
            param($sender, $eventArgs)
            $msg = "Manifest Deleted: $($eventArgs.FullPath)"
            Write-Log $msg 'EVENT'
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
                    if (-not $check.MicrosoftSigned -or -not $check.SafeLocation -or $check.UserWritable -or $check.SuspiciousArgs -or -not $check.Exists) { $sev = 'ALERT' }
                    Write-Log ("Service ImagePath change [{0}]: {1} (Exe={2} Exists={3} MSFT={4} SafeLoc={5} UserWritable={6} SuspArgs={7})" -f $svcLabel, $cmd, $check.Exe, $check.Exists, $check.MicrosoftSigned, $check.SafeLocation, $check.UserWritable, $check.SuspiciousArgs) $sev
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
                    # Re-enumerate manifests and update file watchers
                    $manifests = Enumerate-NMHManifests
                    foreach ($m in $manifests) { Start-ManifestWatcher $m.Manifest }
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

        # Emit alerts based on heuristics
        foreach ($s in $snap.Services) {
            if (-not $s.Exists -or -not $s.MicrosoftSigned -or -not $s.SafeLocation -or $s.UserWritable -or $s.SuspiciousArgs) {
                Write-Log ("ALERT: Service {0} ImagePath suspicious. Exists={1} MSFT={2} SafeLoc={3} UserWritable={4} SuspArgs={5} ImagePath={6}" -f $s.Service, $s.Exists, $s.MicrosoftSigned, $s.SafeLocation, $s.UserWritable, $s.SuspiciousArgs, $s.ImagePath) 'ALERT'
            }
        }
        foreach ($n in $snap.NMH) {
            $m = $n.Manifest
            if (-not $m.JsonValid -or $m.ManifestUserWritable -or $m.NativeUserWritable -or -not $m.NativeExists) {
                Write-Log ("ALERT: NMH {0} ({1}) manifest/native issues. Manifest={2} Native={3} JsonValid={4} ManWritable={5} NativeWritable={6} NativeExists={7}" -f $n.Host, $n.Hive, $m.Manifest, $m.NativePath, $m.JsonValid, $m.ManifestUserWritable, $m.NativeUserWritable, $m.NativeExists) 'ALERT'
            }
        }
        # Prime file watchers for known manifests
        $manifests = Enumerate-NMHManifests
        foreach ($m in $manifests) { Start-ManifestWatcher $m.Manifest }
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

    # Start watchers
    Write-Log "Starting continuous registry + manifest watchers..."
    Register-RegistryWatchers
    # Prime watchers for current manifests
    $manifests = Enumerate-NMHManifests
    foreach ($m in $manifests) { Start-ManifestWatcher $m.Manifest }

    try {
        while ($true) {
            $evt = Wait-Event -Timeout 2
            if ($evt) {
                # Messages are already logged by actions; drain queue
                Remove-Event -EventIdentifier $evt.EventIdentifier | Out-Null
            }
        }
    }
    finally {
        foreach ($s in $RegSubs) { Unregister-Event -SubscriptionId $s.Id -ErrorAction SilentlyContinue }
        Get-Event | Remove-Event -ErrorAction SilentlyContinue
        foreach ($w in $FSWatchers) { $w.EnableRaisingEvents = $false; $w.Dispose() }
        Write-Log "Watchers stopped."
    }
    <# Registers a Scheduled Task to run the Edge/NativeHost monitor at logon and every 10 minutes. Run as admin. #>
    param(
        [string]$ScriptPath = "C:\ProgramData\RegDefense\EdgeHijack\Monitor-EdgeNativeHostHijack.ps1"
    )

    # Ensure destination and copy
    $src = "e:\X12\Security-Defenses\monitors\Monitor-EdgeNativeHostHijack.ps1"
    New-Item -ItemType Directory -Path (Split-Path $ScriptPath) -Force | Out-Null
    Copy-Item -Path $src -Destination $ScriptPath -Force

    # Create baseline if missing
    if (-not (Test-Path -LiteralPath (Join-Path (Split-Path $ScriptPath) 'baseline.json'))) {
        powershell -NoProfile -ExecutionPolicy Bypass -File $ScriptPath -ReBaseline
    }

    # Run continuous monitor
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" -Continuous -EmitEventLog"
    $trLogon = New-ScheduledTaskTrigger -AtLogOn
    $trOnce = New-ScheduledTaskTrigger -Once (Get-Date).AddMinutes(1)
    $trOnce.Repetition = (New-ScheduledTaskTrigger -Once (Get-Date)).Repetition
    $trOnce.Repetition.Interval = "PT10M"
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest

    Register-ScheduledTask -TaskName "RegDefense_EdgeNativeHost_Monitor" -Action $action -Trigger @($trLogon, $trOnce) -Principal $principal -Force | Out-Null
    Write-Host "Scheduled Task 'RegDefense_EdgeNativeHost_Monitor' registered."
    <!-- Sysmon include rules for Edge Update service hijack and Native Messaging Hosts -->
    <Sysmon schemaversion="4.90">
    <EventFiltering>
    <!-- ProcessCreate: broad capture of Edge update and msedge children -->
    <ProcessCreate onmatch="include">
    <Image condition="contains">\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe</Image>
    <ParentImage condition="contains">\msedge.exe</ParentImage>
    </ProcessCreate>

    <!-- Registry: Services ImagePath -->
    <RegistryEvent onmatch="include">
    <TargetObject condition="end with">\SYSTEM\CurrentControlSet\Services\edgeupdate\ImagePath</TargetObject>
    <TargetObject condition="end with">\SYSTEM\CurrentControlSet\Services\edgeupdatem\ImagePath</TargetObject>

    <!-- Native Messaging Hosts (Edge/Chrome), HKLM/HKCU -->
    <TargetObject condition="contains">\SOFTWARE\Microsoft\Edge\NativeMessagingHosts\</TargetObject>
    <TargetObject condition="contains">\SOFTWARE\Google\Chrome\NativeMessagingHosts\</TargetObject>
    </RegistryEvent>

    <!-- File create/change for Native Messaging Host manifests -->
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