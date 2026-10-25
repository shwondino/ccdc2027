#Requires -Version 5.1
<#
.SYNOPSIS
    Detects RID hijacking on the local machine (registry + event logs) and prints remediation steps. Read-only.

.DESCRIPTION
    ATTACK
    - With SYSTEM rights, an attacker edits the RID inside a local account's SAM "F" value so it gets another account's privileges at logon.
    SCOPE
    - Local accounts only; domain account RIDs live in AD, not in this registry.

    REGISTRY CHECKS (need SYSTEM; the script borrows winlogon.exe's SYSTEM token in-process while reading the SAM, no task or PsExec)
    - Compares the RID in each HKLM\SAM\SAM\Domains\Account\Users\<RID>\F value (offset 0x30) with its key name.
    - Reads each account's name-to-RID mapping from Users\Names\<account>.
    - Flags duplicate RIDs, dangling or orphan name mappings, and an enabled Guest account.
    - Reports each flagged account's key last-write time, last logon, password-set time and raw F bytes.

    LOG CHECKS
    - Security 4624: local logon whose token RID differs from the account's real RID (works on default auditing).
    - Security 4657/4663: access or changes to the SAM user keys (needs Audit Registry plus a SACL on that key).
    - Security 4688: command lines touching the SAM user keys, "RID hijack" tools or "reg save HKLM\SAM" (needs command-line logging).
    - PowerShell 4104: the same patterns in script blocks (needs script block logging; this script's own entries are ignored).
    - Sysmon 13: registry value sets on the SAM user keys (needs Sysmon logging registry sets).
    - Security 4720/4722/4724/4732: creation, enabling, password reset and local-group additions, only for accounts flagged by the checks above.

    OUTPUT
    - Findings, affected accounts, log evidence, a timeline with the earliest-evidence estimate, remediation steps and audit-coverage gaps.
    - Key last-write time also changes on normal logons, so treat it as a lower bound and use the earliest log event as the start estimate.

.PARAMETER DaysBack
    Event-log look-back in days (default 90).
.PARAMETER MaxEventsPerQuery
    Cap on events read per query, newest first (default 20000).
.PARAMETER ReportPath
    Where to save the full JSON report (default: C:\ProgramData\RIDHijackCheck\RID-Report_<host>_<timestamp>.json, always saved).

.EXAMPLE
    .\Detect-RIDHijacking.ps1 -DaysBack 180      (or paste the whole script into an elevated PowerShell window)
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 3650)][int]$DaysBack = 90,
    [int]$MaxEventsPerQuery = 20000,
    [string]$ReportPath
)

# RIDHIJACK-DETECTOR-MARKER  (lets this script ignore its own PowerShell script-block log entries)
$ErrorActionPreference = 'Continue'
if (-not $DaysBack) { $DaysBack = 90 }                 # defaults also apply if the code is pasted into a console
if (-not $MaxEventsPerQuery) { $MaxEventsPerQuery = 20000 }
# Script file name (empty if the code was pasted into a console); used to ignore this script's own log entries.
$ScriptName = if ($PSCommandPath) { Split-Path $PSCommandPath -Leaf } else { $null }
# This tool's own source necessarily contains the strings it hunts for, and PowerShell logs every function body as its own
# script block (4104). Blocks matching this signature (any version of this tool) are ignored by the 4104 check.
$OwnSignature = 'RIDHIJACK-DETECTOR-MARKER|\b(Add-Finding|Add-Hit|Write-Section|Get-RidLabel|Invoke-AsSystem|ConvertTo-EvObj|Get-IdXPath|Get-SamData|Get-DefaultValueType|Get-KeyLastWrite|Test-SamRegistry|Show-Remediation|Show-Report)\b|this script changed nothing|ProcessCreationIncludeCmdLine_Enabled'

$WellKnownRids = @{ 500 = 'Administrator (built-in)'; 501 = 'Guest'; 502 = 'krbtgt'; 503 = 'DefaultAccount'
    504 = 'WDAGUtilityAccount'; 512 = 'Domain Admins'; 518 = 'Schema Admins'; 519 = 'Enterprise Admins'; 544 = 'Administrators (group)' }
$PrivilegedRids = @(500, 502, 512, 518, 519, 544)

#region ---------- helpers ----------
# Each helper type is loaded on its own, so a stale copy from an earlier run in the same PowerShell window cannot hide a newer one.
if (-not ('SysTok' -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.ComponentModel;
public static class SysTok {
    [StructLayout(LayoutKind.Sequential, Pack = 4)] struct TP { public int Count; public long Luid; public int Attr; }
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr p, uint access, out IntPtr tok);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool DuplicateTokenEx(IntPtr t, uint access, IntPtr attr, int level, int type, out IntPtr dup);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool ImpersonateLoggedOnUser(IntPtr t);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool RevertToSelf();
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool LookupPrivilegeValueW(string sys, string name, out long luid);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool AdjustTokenPrivileges(IntPtr t, bool disableAll, ref TP ns, int len, IntPtr prev, IntPtr retLen);
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    public static void Enter(int pid) {
        IntPtr me, hp = IntPtr.Zero, tok = IntPtr.Zero, dup = IntPtr.Zero;
        try {
            if (!OpenProcessToken(GetCurrentProcess(), 0x28, out me)) throw new Win32Exception();   // ADJUST_PRIVILEGES | QUERY
            TP tp = new TP(); tp.Count = 1; tp.Attr = 2;                                              // SE_PRIVILEGE_ENABLED
            if (!LookupPrivilegeValueW(null, "SeDebugPrivilege", out tp.Luid)) throw new Win32Exception();
            AdjustTokenPrivileges(me, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            CloseHandle(me);
            hp = OpenProcess(0x1000, false, pid);                                                     // QUERY_LIMITED_INFORMATION
            if (hp == IntPtr.Zero) hp = OpenProcess(0x0400, false, pid);                              // fallback: QUERY_INFORMATION
            if (hp == IntPtr.Zero) throw new Win32Exception();
            if (!OpenProcessToken(hp, 0x0A, out tok)) throw new Win32Exception();                     // DUPLICATE | QUERY
            if (!DuplicateTokenEx(tok, 0x02000000, IntPtr.Zero, 2, 2, out dup)) throw new Win32Exception(); // impersonation token
            if (!ImpersonateLoggedOnUser(dup)) throw new Win32Exception();
        } finally {
            if (dup != IntPtr.Zero) CloseHandle(dup);
            if (tok != IntPtr.Zero) CloseHandle(tok);
            if (hp != IntPtr.Zero) CloseHandle(hp);
        }
    }
    public static void Exit() { RevertToSelf(); }
}
"@
}
if (-not ('RidNative' -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.ComponentModel;
public static class RidNative {
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    public static extern int RegQueryValueExW(IntPtr hKey, string lpValueName, IntPtr lpReserved,
        out uint lpType, IntPtr lpData, ref uint lpcbData);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    public static extern int RegQueryInfoKeyW(IntPtr hKey, IntPtr lpClass, IntPtr lpcchClass, IntPtr lpReserved,
        IntPtr lpcSubKeys, IntPtr lpcbMaxSubKeyLen, IntPtr lpcbMaxClassLen, IntPtr lpcValues,
        IntPtr lpcbMaxValueNameLen, IntPtr lpcbMaxValueLen, IntPtr lpcbSecurityDescriptor, out long lpftLastWriteTime);
}
"@
}

function Get-KeyLastWrite([Microsoft.Win32.RegistryKey]$Key) {
    $ft = [long]0; $z = [IntPtr]::Zero
    $rc = [RidNative]::RegQueryInfoKeyW($Key.Handle.DangerousGetHandle(), $z, $z, $z, $z, $z, $z, $z, $z, $z, $z, [ref]$ft)
    if ($rc -eq 0 -and $ft -gt 0) { return [DateTime]::FromFileTimeUtc($ft) }
    return $null
}

# A Names\<user> entry stores the account's RID in the *type* field of its (Default) value.
function Get-DefaultValueType([Microsoft.Win32.RegistryKey]$Key) {
    $type = [uint32]0; $cb = [uint32]0
    $rc = [RidNative]::RegQueryValueExW($Key.Handle.DangerousGetHandle(), '', [IntPtr]::Zero, [ref]$type, [IntPtr]::Zero, [ref]$cb)
    if ($rc -eq 0) { return [int64]$type }
    return $null
}

function Convert-FileTimeSafe([long]$v) {
    if ($v -le 0 -or $v -ge 0x7FFFFFFFFFFFFFFF) { return $null }
    try { return [DateTime]::FromFileTimeUtc($v) } catch { return $null }
}

function Get-RidLabel([int64]$Rid) {
    if ($Rid -le [int]::MaxValue -and $WellKnownRids.ContainsKey([int]$Rid)) { return $WellKnownRids[[int]$Rid] }
    if ($script:RidNames -and $script:RidNames.ContainsKey($Rid)) { return "local account '$($script:RidNames[$Rid])'" }
    return $null
}

function Add-Finding([string]$Severity, [string]$Title, [string]$Detail) {
    $script:Findings += [pscustomobject]@{ Severity = $Severity; Title = $Title; Detail = $Detail }
}
# Kind: 'Evidence' = indicates the attack; 'Context' = related activity
function Add-Hit([datetime]$Time, [string]$Kind, [string]$Severity, [string]$Source, [string]$Title, [string]$Detail) {
    $script:Hits += [pscustomobject]@{ Time = $Time; Kind = $Kind; Severity = $Severity; Source = $Source; Title = $Title; Detail = $Detail }
}

function ConvertTo-EvObj($e) {
    $xml = [xml]$e.ToXml(); $d = @{}
    foreach ($n in @($xml.Event.EventData.Data)) { if ($n -and $n.Name) { $d[$n.Name] = $n.'#text' } }
    if ($xml.Event.UserData -and $xml.Event.UserData.FirstChild) {
        foreach ($c in $xml.Event.UserData.FirstChild.ChildNodes) { $d[$c.Name] = $c.InnerText }
    }
    [pscustomobject]@{ Time = $e.TimeCreated; Id = $e.Id; Data = $d }
}

function Get-EventsXPath([string]$LogName, [string]$XPath) {
    try { return @(Get-WinEvent -LogName $LogName -FilterXPath $XPath -MaxEvents $MaxEventsPerQuery -ErrorAction Stop) }
    catch {
        if ($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound') { $script:Warnings += "Query on '$LogName' failed: $($_.Exception.Message)" }
        return @()
    }
}

function Get-IdXPath([int[]]$Ids, [int64]$Ms) {
    $idPart = ($Ids | ForEach-Object { "EventID=$_" }) -join ' or '
    return "*[System[($idPart) and TimeCreated[timediff(@SystemTime) <= $Ms]]]"
}

function Get-Snippet([string]$Text, [string]$Regex, [int]$Pad = 90) {
    $m = [regex]::Match($Text, $Regex, 'IgnoreCase')
    if (-not $m.Success) { return $Text.Substring(0, [Math]::Min(200, $Text.Length)) }
    $s = [Math]::Max(0, $m.Index - $Pad); $l = [Math]::Min($Text.Length - $s, $m.Length + 2 * $Pad)
    return ($Text.Substring($s, $l) -replace '\s+', ' ')
}
#endregion

#region ---------- SAM registry analysis ----------
# Run a scriptblock as SYSTEM on this thread (SAM is readable by SYSTEM only), then always revert.
function Invoke-AsSystem([scriptblock]$Code) {
    $isSys = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq 'S-1-5-18'
    if ($isSys) { return (& $Code) }
    $wl = Get-Process -Name winlogon -ErrorAction Stop | Select-Object -First 1
    [SysTok]::Enter($wl.Id)
    try { return (& $Code) } finally { [SysTok]::Exit() }
}

function Get-SamData {
    $base = 'SAM\SAM\Domains\Account'
    $acctKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($base)
    $users = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("$base\Users")
    if (-not $users -or -not $acctKey) { throw "Cannot open HKLM\$base (SYSTEM rights required)." }

    $machineSid = $null
    $v = $acctKey.GetValue('V')
    if ($v -is [byte[]] -and $v.Length -ge 12) {
        $o = $v.Length - 12
        $machineSid = 'S-1-5-21-{0}-{1}-{2}' -f [BitConverter]::ToUInt32($v, $o), [BitConverter]::ToUInt32($v, $o + 4), [BitConverter]::ToUInt32($v, $o + 8)
    }

    $nameMap = @()
    $names = $users.OpenSubKey('Names')
    if ($names) {
        foreach ($n in $names.GetSubKeyNames()) {
            $nk = $names.OpenSubKey($n)
            if ($nk) { $nameMap += [pscustomobject]@{ Name = $n; Rid = (Get-DefaultValueType $nk) }; $nk.Close() }
        }
    }

    $accts = @()
    foreach ($sub in $users.GetSubKeyNames()) {
        if ($sub -notmatch '^[0-9A-Fa-f]{8}$') { continue }
        $uk = $users.OpenSubKey($sub); if (-not $uk) { continue }
        $keyRid = [int64][Convert]::ToUInt32($sub, 16)
        $f = $uk.GetValue('F')
        $o = [ordered]@{
            KeyName = $sub.ToUpper(); KeyRid = $keyRid
            Names = @($nameMap | Where-Object { $_.Rid -eq $keyRid } | ForEach-Object { $_.Name })
            KeyLastWriteUtc = (Get-KeyLastWrite $uk)
            FRid = $null; Disabled = $null; LastLogonUtc = $null; PwdLastSetUtc = $null; LogonCount = $null; FHex = $null; FLabel = $null
        }
        if ($f -is [byte[]] -and $f.Length -ge 0x44) {
            $o.FRid = [int64][BitConverter]::ToUInt32($f, 0x30)
            $o.Disabled = ([BitConverter]::ToUInt16($f, 0x38) -band 1) -ne 0
            $o.LastLogonUtc = Convert-FileTimeSafe ([BitConverter]::ToInt64($f, 0x08))
            $o.PwdLastSetUtc = Convert-FileTimeSafe ([BitConverter]::ToInt64($f, 0x18))
            $o.LogonCount = [int][BitConverter]::ToUInt16($f, 0x42)
            $o.FHex = ($f | ForEach-Object { '{0:X2}' -f $_ }) -join ''
        }
        $accts += [pscustomobject]$o
        $uk.Close()
    }
    [pscustomobject]@{ Accounts = $accts; NameMap = $nameMap; MachineSid = $machineSid }
}

function Test-SamRegistry($sam) {
    $script:RidNames = @{}
    foreach ($n in $sam.NameMap) { if ($n.Rid) { $script:RidNames[[int64]$n.Rid] = $n.Name } }

    $flagged = @()
    foreach ($a in $sam.Accounts) {
        $disp = if ($a.Names.Count) { $a.Names -join ', ' } else { '<no Names entry>' }
        if ($null -eq $a.FRid) { Add-Finding 'MEDIUM' 'SAM F value missing/unreadable' "Key $($a.KeyName) ($disp) has no valid F value."; continue }
        if ($a.FRid -ne $a.KeyRid) {
            $label = Get-RidLabel $a.FRid
            $a.FLabel = $label
            $priv = $PrivilegedRids -contains $a.FRid
            $state = if ($a.Disabled) { 'DISABLED' } else { 'ENABLED' }
            $labelTxt = ''; if ($label) { $labelTxt = " = $label" }
            $privTxt = ''; if ($priv) { $privTxt = ' [PRIVILEGED TARGET]' }
            Add-Finding 'CRITICAL' 'RID hijacked: F-value RID does not match key RID' (
                "Account '$disp' lives in key $($a.KeyName) (RID $($a.KeyRid)) but its F value claims RID $($a.FRid)" +
                "$labelTxt$privTxt. Account is $state. " +
                "It will receive the token of RID $($a.FRid) at logon. This never happens legitimately.")
            $flagged += $a
        }
    }
    foreach ($g in ($sam.Accounts | Where-Object { $null -ne $_.FRid } | Group-Object FRid | Where-Object { $_.Count -gt 1 })) {
        Add-Finding 'CRITICAL' "Duplicate RID $($g.Name) in F values" ("Claimed by: " + (($g.Group | ForEach-Object { "$($_.KeyName)[$($_.Names -join ',')]" }) -join '; '))
    }
    foreach ($n in $sam.NameMap) {
        if ($n.Rid -and -not ($sam.Accounts | Where-Object { $_.KeyRid -eq $n.Rid })) {
            Add-Finding 'MEDIUM' 'Names entry points to a missing user key' "'$($n.Name)' maps to RID $($n.Rid) but key $('{0:X8}' -f $n.Rid) does not exist."
        }
    }
    foreach ($a in $sam.Accounts) {
        if ($a.Names.Count -eq 0) { Add-Finding 'LOW' 'User key with no Names entry (orphan)' "Key $($a.KeyName) (RID $($a.KeyRid)) is not referenced by any account name." }
        if ($a.Names.Count -gt 1) { Add-Finding 'MEDIUM' 'Several names map to one user key' "Key $($a.KeyName): $($a.Names -join ', ')" }
    }
    $guest = $sam.Accounts | Where-Object { $_.KeyRid -eq 501 } | Select-Object -First 1
    if ($guest -and $guest.Disabled -eq $false) {
        Add-Finding 'MEDIUM' 'Guest account (RID 501) is enabled' 'Disabled by default. Attackers often enable Guest, set a password, then hijack its RID.'
    }
    return $flagged
}
#endregion

#region ---------- log analysis ----------
function Search-Logs($sam, $flagged, [int64]$Ms, [string]$ComputerName) {
    $nameToRid = @{}
    foreach ($n in $sam.NameMap) { if ($n.Rid) { $nameToRid[$n.Name] = [int64]$n.Rid } }
    $machineSid = $sam.MachineSid

    # 1. Local logons whose token RID != the RID of the account name used (works on default auditing)
    $suspects = @{}
    $xp = "*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) <= $Ms]]] and *[EventData[Data[@Name='TargetDomainName']='$ComputerName']]"
    foreach ($e in (Get-EventsXPath 'Security' $xp)) {
        $o = ConvertTo-EvObj $e; $d = $o.Data
        $sid = $d['TargetUserSid']; $user = $d['TargetUserName']
        if (-not $sid -or -not $user -or -not $nameToRid.ContainsKey($user)) { continue }
        if ($machineSid -and -not $sid.StartsWith($machineSid + '-')) { continue }
        $actual = [int64]$sid.Substring($sid.LastIndexOf('-') + 1)
        if ($actual -ne $nameToRid[$user]) {
            $lbl = Get-RidLabel $actual
            $lblTxt = ''; if ($lbl) { $lblTxt = " = $lbl" }
            $suspects[$user] = 1
            Add-Hit $o.Time 'Evidence' 'CRITICAL' 'Security 4624' "Logon token RID differs from account RID: $user" (
                "User '$user' (real RID $($nameToRid[$user])) logged on with SID $sid (RID $actual$lblTxt). " +
                "LogonType=$($d['LogonType']) SourceIP=$($d['IpAddress']) Workstation=$($d['WorkstationName']) Process=$($d['ProcessName']) LogonId=$($d['TargetLogonId'])")
        }
    }

    # 2. Registry auditing events on the SAM user keys (needs Audit Registry + SACL)
    foreach ($e in (Get-EventsXPath 'Security' (Get-IdXPath @(4657, 4663) $Ms))) {
        $o = ConvertTo-EvObj $e; $d = $o.Data
        if ($d['ObjectName'] -match 'SAM\\SAM\\Domains\\Account\\Users') {
            Add-Hit $o.Time 'Evidence' 'CRITICAL' "Security $($o.Id)" 'SAM user key accessed/modified' (
                "Object=$($d['ObjectName']) Value=$($d['ObjectValueName']) By=$($d['SubjectDomainName'])\$($d['SubjectUserName']) Process=$($d['ProcessName'])")
        }
    }

    # 3+4. Suspicious command lines (4688) and PowerShell script blocks (4104)
    $patterns = @(
        @{ Name = 'direct SAM user-key access'; Rx = 'SAM\\SAM\\Domains\\Account\\Users|HKLM:\\SAM|HKEY_LOCAL_MACHINE\\SAM\\SAM' }
        @{ Name = 'RID-hijack tooling/keyword'; Rx = 'rid[\s_-]?hijack' }
        @{ Name = 'SAM hive export (related credential access)'; Rx = 'reg(\.exe)?\s+(save|export)\s+["'']?hk(lm|ey_local_machine)\\sam\b' }
    )
    foreach ($e in (Get-EventsXPath 'Security' (Get-IdXPath @(4688) $Ms))) {
        $o = ConvertTo-EvObj $e; $d = $o.Data; $cl = $d['CommandLine']
        if (-not $cl -or ($ScriptName -and $cl -like "*$ScriptName*")) { continue }
        foreach ($p in $patterns) {
            if ($cl -match $p.Rx) {
                Add-Hit $o.Time 'Evidence' 'HIGH' 'Security 4688' "Suspicious process: $($p.Name)" "Process=$($d['NewProcessName']) Parent=$($d['ParentProcessName']) User=$($d['SubjectDomainName'])\$($d['SubjectUserName']) Cmd=...$(Get-Snippet $cl $p.Rx)..."
                break
            }
        }
    }
    $psEvents = @(Get-EventsXPath 'Microsoft-Windows-PowerShell/Operational' (Get-IdXPath @(4104) $Ms) | ForEach-Object { ConvertTo-EvObj $_ })
    $ownIds = @($psEvents | Where-Object { $_.Data['ScriptBlockText'] -match $OwnSignature } | ForEach-Object { $_.Data['ScriptBlockId'] })
    foreach ($o in $psEvents) {
        $d = $o.Data; $txt = $d['ScriptBlockText']
        if (-not $txt -or $ownIds -contains $d['ScriptBlockId'] -or ($ScriptName -and $d['Path'] -and $d['Path'] -like "*$ScriptName")) { continue }
        foreach ($p in $patterns) {
            if ($txt -match $p.Rx) {
                Add-Hit $o.Time 'Evidence' 'HIGH' 'PowerShell 4104' "Suspicious script block: $($p.Name)" "Path=$($d['Path']) Text=...$(Get-Snippet $txt $p.Rx)..."
                break
            }
        }
    }

    # 5. Sysmon event 13 (registry value set) on SAM user keys
    $sysLog = 'Microsoft-Windows-Sysmon/Operational'
    if (Get-WinEvent -ListLog $sysLog -ErrorAction SilentlyContinue) {
        $base = Get-IdXPath @(13) $Ms
        $sysEvents = @()
        try { $sysEvents = @(Get-WinEvent -LogName $sysLog -FilterXPath ($base + " and *[EventData[Data[contains(., 'SAM\SAM\Domains\Account\Users')]]]") -MaxEvents $MaxEventsPerQuery -ErrorAction Stop) }
        catch { if ($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound') { $sysEvents = Get-EventsXPath $sysLog $base } }
        foreach ($e in $sysEvents) {
            $o = ConvertTo-EvObj $e; $d = $o.Data
            if ($d['TargetObject'] -match 'SAM\\SAM\\Domains\\Account\\Users') {
                Add-Hit $o.Time 'Evidence' 'CRITICAL' 'Sysmon 13' 'Registry value set on SAM user key' "Target=$($d['TargetObject']) Image=$($d['Image']) User=$($d['User'])"
            }
        }
    }

    # 6. Account activity (created / enabled / password reset / added to a local group) - ONLY for flagged or suspect accounts
    $names = @{}; $sidToName = @{}
    foreach ($a in $flagged) { foreach ($n in $a.Names) { $names[$n] = 1; if ($machineSid) { $sidToName["$machineSid-$($a.KeyRid)"] = $n } } }
    foreach ($n in $suspects.Keys) { $names[$n] = 1; if ($machineSid -and $nameToRid.ContainsKey($n)) { $sidToName["$machineSid-$($nameToRid[$n])"] = $n } }
    if ($names.Count) {
        $titles = @{ 4720 = 'Account created'; 4722 = 'Account enabled'; 4724 = 'Password reset'; 4732 = 'Added to local group' }
        foreach ($e in (Get-EventsXPath 'Security' (Get-IdXPath @(4720, 4722, 4724, 4732) $Ms))) {
            $o = ConvertTo-EvObj $e; $d = $o.Data
            $who = $null; $what = $titles[[int]$o.Id]
            if ($o.Id -eq 4732) {
                if ($d['MemberSid'] -and $sidToName.ContainsKey($d['MemberSid'])) { $who = $sidToName[$d['MemberSid']]; $what = "Added to local group '$($d['TargetUserName'])'" }
            } elseif ($d['TargetUserName'] -and $names.ContainsKey($d['TargetUserName'])) { $who = $d['TargetUserName'] }
            if ($who) {
                Add-Hit $o.Time 'Context' 'INFO' "Security $($o.Id)" "${what}: $who" "By=$($d['SubjectDomainName'])\$($d['SubjectUserName']) LogonId=$($d['SubjectLogonId'])"
            }
        }
    }
}

function Get-Coverage {
    $items = @()
    $pol = @(
        @{ Name = 'Audit Registry (4657/4663)'; Guid = '{0CCE921E-69AE-11D9-BED3-505054503030}' }
        @{ Name = 'Audit Process Creation (4688)'; Guid = '{0CCE922B-69AE-11D9-BED3-505054503030}' }
        @{ Name = 'Audit Logon (4624)'; Guid = '{0CCE9215-69AE-11D9-BED3-505054503030}' }
        @{ Name = 'Audit User Account Management'; Guid = '{0CCE9235-69AE-11D9-BED3-505054503030}' }
    )
    foreach ($p in $pol) {
        $status = 'unknown'
        try {
            $line = & auditpol.exe /get /subcategory:"$($p.Guid)" /r 2>$null | Where-Object { $_ } | Select-Object -Skip 1 -First 1
            if ($line) { $status = ($line -split ',')[4] }
        } catch {}
        $items += [pscustomobject]@{ Item = $p.Name; Status = $status }
    }
    $cmd = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled
    $st = 'NOT enabled'; if ($cmd -eq 1) { $st = 'enabled' }
    $items += [pscustomobject]@{ Item = 'Command line in 4688'; Status = $st }
    $sbl = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging
    $st = 'NOT enabled (by policy)'; if ($sbl -eq 1) { $st = 'enabled' }
    $items += [pscustomobject]@{ Item = 'PowerShell script block logging'; Status = $st }
    $st = 'NOT installed'; if (Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue) { $st = 'yes' }
    $items += [pscustomobject]@{ Item = 'Sysmon installed'; Status = $st }
    try {
        $samUsersPath = 'HKLM:\SAM\SAM\Domains\Account\Users'
        $aud = Invoke-AsSystem { (Get-Acl -Path $samUsersPath -Audit -ErrorAction Stop).Audit }
        $st = 'NOT present'; if (@($aud).Count) { $st = 'present' }
        $items += [pscustomobject]@{ Item = 'Audit SACL on SAM\...\Users key'; Status = $st }
    } catch { $items += [pscustomobject]@{ Item = 'Audit SACL on SAM\...\Users key'; Status = 'unknown' } }
    try {
        $old = Get-WinEvent -LogName Security -Oldest -MaxEvents 1 -ErrorAction Stop
        $items += [pscustomobject]@{ Item = 'Oldest event in Security log'; Status = $old.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') }
    } catch {}
    return $items
}
#endregion

function Invoke-Collection {
    $script:Findings = @()
    $script:Hits = @()
    $script:Warnings = @()
    $ms = [int64]$DaysBack * 86400000
    $cs = Get-CimInstance Win32_ComputerSystem
    $roles = @{ 0 = 'Standalone workstation'; 1 = 'Member workstation'; 2 = 'Standalone server'; 3 = 'Member server'; 4 = 'Backup domain controller'; 5 = 'Primary domain controller' }

    $sam = $null; $flagged = @()
    try { $sam = Invoke-AsSystem { Get-SamData }; $flagged = @(Test-SamRegistry $sam) }
    catch { $script:Warnings += "SAM analysis failed: $($_.Exception.Message)" }
    if ($sam) { Search-Logs $sam $flagged $ms $cs.Name }

    $admins = @()
    try { $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { "$($_.Name) [$($_.ObjectClass)] $($_.SID.Value)" }) } catch {}

    $machineSid = $null
    if ($null -ne $sam) { $machineSid = $sam.MachineSid }
    $res = [ordered]@{}
    $res['ComputerName'] = $cs.Name
    $res['Domain'] = $cs.Domain
    $res['Role'] = $roles[[int]$cs.DomainRole]
    $res['RanAtUtc'] = (Get-Date).ToUniversalTime()
    $res['DaysBack'] = $DaysBack
    $res['SamRead'] = ($null -ne $sam)
    $res['MachineSid'] = $machineSid
    $res['Flagged'] = @($flagged)
    $res['Findings'] = @($script:Findings)
    $res['Hits'] = @($script:Hits | Sort-Object Time)
    $res['Coverage'] = @(Get-Coverage)
    $res['LocalAdmins'] = @($admins)
    $res['Warnings'] = @($script:Warnings)
    return [pscustomobject]$res
}

#region ---------- output ----------
function Get-SevColor($s) { switch ($s) { 'CRITICAL' { 'Red' } 'HIGH' { 'Magenta' } 'MEDIUM' { 'Yellow' } 'LOW' { 'Cyan' } default { 'Gray' } } }
function Write-Section($t) { Write-Host ''; Write-Host ('=' * 100) -ForegroundColor DarkGray; Write-Host " $t" -ForegroundColor White; Write-Host ('=' * 100) -ForegroundColor DarkGray }
function Format-Utc($d) { if ($d) { ([datetime]$d).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') + ' UTC' } else { 'n/a' } }

function Show-Report($r) {
    Write-Section 'RID HIJACKING CHECK'
    Write-Host "Host: $($r.ComputerName) ($($r.Role); $($r.Domain))   Machine SID: $($r.MachineSid)"
    Write-Host "Run at: $(Format-Utc $r.RanAtUtc)   Log look-back: $($r.DaysBack) days"

    $evidence = @($r.Hits | Where-Object { $_.Kind -eq 'Evidence' })
    $detected = ($r.Flagged.Count -gt 0) -or ($evidence.Count -gt 0) -or [bool]($r.Findings | Where-Object { $_.Severity -eq 'CRITICAL' })
    Write-Host ''
    if (-not $r.SamRead -and -not $detected) { Write-Host '  INCOMPLETE: the SAM registry could not be read, so the main check did not run (see warnings below).' -ForegroundColor Yellow }
    elseif ($detected) { Write-Host '  >>> RID HIJACKING INDICATORS FOUND <<<' -ForegroundColor Red -BackgroundColor Black }
    else { Write-Host '  No RID hijacking indicators found in the registry or in the available logs.' -ForegroundColor Green }

    Write-Section 'FINDINGS'
    if (-not $r.Findings.Count) { Write-Host ' none' }
    foreach ($f in ($r.Findings | Sort-Object @{e = { @('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO').IndexOf($_.Severity) } })) {
        Write-Host " [$($f.Severity)] $($f.Title)" -ForegroundColor (Get-SevColor $f.Severity)
        Write-Host "     $($f.Detail)"
    }

    foreach ($a in $r.Flagged) {
        if ($a -eq $r.Flagged[0]) { Write-Section 'AFFECTED ACCOUNTS (SAM registry)' }
        Write-Host " Account(s): $($a.Names -join ', ')" -ForegroundColor Red
        Write-Host "   Key: HKLM\SAM\SAM\Domains\Account\Users\$($a.KeyName) (real RID $($a.KeyRid)); F claims RID $($a.FRid) $($a.FLabel)"
        Write-Host "   Disabled: $($a.Disabled)   Last logon: $(Format-Utc $a.LastLogonUtc)   Logons: $($a.LogonCount)   Password set: $(Format-Utc $a.PwdLastSetUtc)"
        Write-Host "   Key last-write: $(Format-Utc $a.KeyLastWriteUtc)  (lower bound only - normal logons also update it)"
        Write-Host "   Raw F: $($a.FHex)"
    }

    Write-Section 'LOG EVIDENCE'
    if (-not $r.Hits.Count) { Write-Host ' no matching events in the look-back window' }
    foreach ($h in $r.Hits) {
        Write-Host (" {0}  [{1}] {2} ({3})" -f (Format-Utc $h.Time), $h.Source, $h.Title, $h.Kind) -ForegroundColor (Get-SevColor $h.Severity)
        Write-Host "     $($h.Detail)"
    }

    Write-Section 'TIMELINE / ESTIMATED START'
    $rows = @()
    foreach ($h in @($r.Hits)) { if ($h -and $h.Time) { $rows += [pscustomobject]@{ Time = [datetime]$h.Time; What = "[$($h.Source)] $($h.Title)"; Type = $h.Kind } } }
    foreach ($a in $r.Flagged) {
        if ($a.KeyLastWriteUtc) { $rows += [pscustomobject]@{ Time = [datetime]$a.KeyLastWriteUtc; What = "SAM key $($a.KeyName) last written ($($a.Names -join ','))"; Type = 'Registry' } }
    }
    foreach ($x in ($rows | Sort-Object Time)) { Write-Host (" {0}  {1}  ({2})" -f (Format-Utc $x.Time), $x.What, $x.Type) }
    $first = $rows | Where-Object { $_.Type -eq 'Evidence' } | Sort-Object Time | Select-Object -First 1
    if ($first) { Write-Host "`n Earliest log evidence: $(Format-Utc $first.Time) -> start investigating at or before this time." -ForegroundColor Yellow }
    elseif ($detected) { Write-Host "`n No log evidence found, so the start time cannot be determined (see coverage gaps below)." -ForegroundColor Yellow }
    elseif (-not $rows.Count) { Write-Host ' nothing to show' }

    if ($r.LocalAdmins.Count) { Write-Section 'CURRENT LOCAL ADMINISTRATORS (context)'; $r.LocalAdmins | ForEach-Object { Write-Host "  $_" } }
    if ($detected) { Show-Remediation $r }

    Write-Section 'LOG / AUDIT COVERAGE (blind spots limit what can be proven)'
    foreach ($c in $r.Coverage) {
        $col = 'Gray'; if ($c.Status -match 'NOT|No Auditing|unknown') { $col = 'Yellow' }
        Write-Host ("  {0,-40} {1}" -f $c.Item, $c.Status) -ForegroundColor $col
    }
    $r.Warnings | ForEach-Object { Write-Host "  warning: $_" -ForegroundColor Yellow }
    if (-not $detected) {
        Write-Host "`n The registry check is authoritative for the CURRENT state; the logs cover the past, and gaps above mean old activity may be invisible." -ForegroundColor DarkGray
    }
}

function Write-Step([string]$n, [string]$t) { Write-Host ''; Write-Host " $n. $t" -ForegroundColor White }
function Write-Note([string]$t) { Write-Host "    $t" }
function Write-Cmd([string]$t) { Write-Host "      $t" -ForegroundColor Cyan }

function Show-Remediation($r) {
    Write-Section 'REMEDIATION (this script changed nothing)'

    Write-Step 1 'CONTAIN'
    Write-Note 'The attacker needed SYSTEM, so treat this host as fully compromised.'
    Write-Note 'Isolate it from the network and open an incident.'

    Write-Step 2 'PRESERVE EVIDENCE (before changing anything)'
    Write-Cmd 'mkdir C:\IR'
    Write-Cmd 'wevtutil epl Security C:\IR\Security.evtx'
    Write-Cmd 'wevtutil epl Microsoft-Windows-PowerShell/Operational C:\IR\PowerShell.evtx'
    Write-Cmd 'reg save HKLM\SAM C:\IR\SAM.hiv'
    Write-Cmd 'reg save HKLM\SYSTEM C:\IR\SYSTEM.hiv'

    Write-Step 3 'DISABLE EACH HIJACKED ACCOUNT, THEN REMOVE OR REPAIR IT'
    foreach ($a in $r.Flagged) {
        $nm = if ($a.Names.Count) { $a.Names[0] } else { $a.KeyName }
        Write-Host ''
        Write-Host "    Account '$nm'   (key $($a.KeyName): real RID $($a.KeyRid), F value says $($a.FRid))" -ForegroundColor Yellow
        Write-Note '  a) Disable it now:'
        Write-Cmd "  net user `"$nm`" /active:no"
        if ($a.KeyRid -ge 1000) {
            Write-Note '  b) Preferred: once evidence is saved, delete it and recreate it with a NEW password:'
            Write-Cmd "  net user `"$nm`" /delete"
        } else {
            Write-Note '  b) Built-in accounts cannot be deleted: keep it disabled and repair it in step 4.'
        }
    }

    Write-Step 4 'REPAIR THE RID IN PLACE (only if the account must be kept; needs SYSTEM)'
    Write-Note 'Paste this whole block into an elevated PowerShell window. It runs the fix once as SYSTEM,'
    Write-Note 'then removes the task and the file. Re-run this script afterwards to confirm.'
    Write-Host ''
    Write-Cmd 'New-Item -ItemType Directory -Path C:\IR -Force | Out-Null'
    Write-Cmd 'Set-Content C:\IR\RidFix.ps1 -Value @('
    $lines = @()
    foreach ($a in $r.Flagged) {
        $key = "HKLM:\SAM\SAM\Domains\Account\Users\$($a.KeyName)"
        $lines += "'`$f = (Get-ItemProperty $key).F'"
        $lines += "'[BitConverter]::GetBytes([uint32]$($a.KeyRid)).CopyTo(`$f, 0x30)'"
        $lines += "'Set-ItemProperty $key -Name F -Value `$f -Type Binary'"
    }
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $comma = ','; if ($i -eq $lines.Count - 1) { $comma = '' }
        Write-Cmd "  $($lines[$i])$comma"
    }
    Write-Cmd ')'
    Write-Cmd "`$act = New-ScheduledTaskAction -Execute powershell.exe -Argument '-NoProfile -ExecutionPolicy Bypass -File C:\IR\RidFix.ps1'"
    Write-Cmd '$prn = New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest'
    Write-Cmd 'Register-ScheduledTask -TaskName RidFix -Action $act -Principal $prn | Out-Null'
    Write-Cmd 'Start-ScheduledTask -TaskName RidFix'
    Write-Cmd 'Start-Sleep -Seconds 5'
    Write-Cmd 'Unregister-ScheduledTask -TaskName RidFix -Confirm:$false'
    Write-Cmd 'Remove-Item C:\IR\RidFix.ps1'

    Write-Step 5 'RESET CREDENTIALS'
    Write-Note 'Assume local hashes, LSA secrets and cached domain credentials on this host are exposed.'
    Write-Note 'Reset every local account (including the built-in Administrator) and every domain or service'
    Write-Note 'account that logged on here. If Guest was enabled:  net user guest /active:no'

    Write-Step 6 'REBOOT AND VERIFY'
    Write-Note 'Reboot, then re-run this script to confirm no mismatch remains.'

    Write-Step 7 'HUNT'
    Write-Note 'Find out how they got SYSTEM: check new services, scheduled tasks, Run keys, WMI subscriptions'
    Write-Note 'and new local admins. Use the logon evidence above (source IP, workstation, process) to find other'
    Write-Note 'machines touched. Rebuild from a clean image if you cannot explain it.'

    Write-Step 8 'PREVENT / DETECT NEXT TIME'
    Write-Note 'Audit Registry plus a SACL on HKLM\SAM\SAM\Domains\Account\Users, 4688 with command lines,'
    Write-Note 'script block logging, Sysmon, log forwarding to a SIEM, alerts on 4624 RID/name mismatch'
    Write-Note 'and on Guest being enabled (4722), LAPS, and fewer local admins.'
}
#endregion

# ---------------- main ----------------
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$isSystem = $id.User.Value -eq 'S-1-5-18'
$isAdmin = (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin -and -not $isSystem) { Write-Warning 'Run this script from an elevated (Administrator) PowerShell prompt.'; return }

try { $result = Invoke-Collection }
catch { Write-Warning "Unexpected error: $($_.Exception.Message) (script line $($_.InvocationInfo.ScriptLineNumber))"; return }
if (-not $result) { Write-Warning 'No result was produced.'; return }
Show-Report $result
# Always save a JSON copy of the results (default location, no input needed; also works when pasted)
if (-not $ReportPath) {
    $dir = Join-Path $env:ProgramData 'RIDHijackCheck'
    $ReportPath = Join-Path $dir ('RID-Report_{0}_{1}.json' -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd-HHmmss'))
}
try {
    $parent = Split-Path $ReportPath -Parent
    if ($parent -and -not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    $result | ConvertTo-Json -Depth 8 | Set-Content -Path $ReportPath -Encoding UTF8
    Write-Host "`nFull report saved to: $ReportPath" -ForegroundColor Gray
} catch { Write-Warning "Could not save the report: $($_.Exception.Message)" }