<#
.SYNOPSIS
    Runs until stopped (Ctrl+C) and reports every new account creation in detail.

.DESCRIPTION
    Events used (Security log):
        4720  User account created                 (trigger)
        4741  Computer account created             (on by default; -ExcludeComputerAccounts to disable)
        4722  Account enabled                      (related events, on by default)
        4724  Password reset attempt               (  "  )
        4728  Member added to global group         (  "  )
        4732  Member added to local/domain-local   (  "  )
        4756  Member added to universal group      (  "  )
        4624  Logon                                (a) correlated to the creator by Logon ID -> source IP
                                                   (b) first-logon tracking for the NEW account
        4768  Kerberos TGT request                 first-logon tracking for new DOMAIN accounts
                                                   By default only the FIRST logon per (machine, account, source IP,
                                                   logon type) is shown. -ReportAllNewAccountLogons shows every one.

    Works for DOMAIN accounts (DC) and LOCAL accounts (member servers / workstations / CA,
    via -ComputerName). Local-account enrichment uses PowerShell remoting (WinRM) when the
    machine is not the one running the script.

    Output: coloured console report. Optionally (-LogPath) one JSON object per event is
    appended to a file you choose.

    READ-ONLY BY DESIGN: this script performs no remediation or enforcement. It never disables,
    deletes, modifies or creates accounts or groups, never changes policy, ACLs, services or the
    event logs, and never blocks or kills anything. What it touches:
        - reads the Security log (Get-WinEvent) and the audit policy of each monitored machine (auditpol /get)
        - read-only AD queries (Get-ADObject / Get-ADUser) and DNS PTR lookups (Resolve-DnsName)
        - read-only queries on OTHER machines over WinRM (Get-LocalUser, Get-LocalGroup,
          Get-LocalGroupMember, auditpol /get, Get-CimInstance); turn off with -DisableRemoteEnrichment
        - writes ONLY to the console, plus to the file given in -LogPath if you supply one
          (put {date} in the name for one file per day). It never rotates, renames, deletes or
          re-permissions files: retention and access control of the log are yours to manage.

.EXAMPLE
    .\Watch-AccountCreation.ps1

.EXAMPLE
    .\Watch-AccountCreation.ps1 -ComputerName DC01,FILES01,CA01,WS01 `
        -ExpectedCreators 'adm-jsmith','adm-mjones' -TrustedSourceIPs '10.0.0.5','10.0.0.20'

.NOTES
    Run elevated on the DC. ASCII-only on purpose (Windows PowerShell 5.1 safe).
    Audit policy needed: User Account Management, Computer Account Management,
    Security Group Management, Logon, Kerberos Authentication Service (all Success).
#>
#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string[]]$ComputerName = @($env:COMPUTERNAME),
    [int]$PollSeconds = 5,
    [int]$LogonLookbackHours = 48,
    [string]$LogPath = '',                 # optional JSON-lines file; '{date}' in the name = one file per day. Empty = console only.
    [switch]$DisableRemoteEnrichment,      # skip WinRM queries to other machines (local-account details)
    [switch]$ExcludeComputerAccounts,
    [switch]$ExcludeRelated,
    [switch]$ExcludeFirstLogonTracking,
    [switch]$ReportAllNewAccountLogons,    # default: only first-seen (machine, account, IP, logon type) combos
    [int]$FirstLogonWatchHours = 24,
    [string[]]$ExpectedCreators = @(),     # SamAccountNames allowed to create accounts. Empty = don't check.
    [string[]]$TrustedSourceIPs = @(),     # Admin workstation IPs. Empty = don't check.
    [int]$BusinessStartHour = 7,
    [int]$BusinessEndHour = 19,
    [int]$BurstThreshold = 3,              # this many creations ...
    [int]$BurstWindowMinutes = 10          # ... inside this window raises an alert
)

# ---------------------------------------------------------------------------
# Static lookup tables
# ---------------------------------------------------------------------------
$LogonTypes = @{
    0 = 'System'; 2 = 'Interactive (console)'; 3 = 'Network'; 4 = 'Batch'; 5 = 'Service'
    7 = 'Unlock'; 8 = 'NetworkCleartext'; 9 = 'NewCredentials (runas /netonly)'
    10 = 'RemoteInteractive (RDP)'; 11 = 'CachedInteractive'
}

$UacFlagList = @(
    , @(0x0001, 'SCRIPT')
    , @(0x0002, 'ACCOUNTDISABLE')
    , @(0x0008, 'HOMEDIR_REQUIRED')
    , @(0x0010, 'LOCKOUT')
    , @(0x0020, 'PASSWD_NOTREQD')
    , @(0x0040, 'PASSWD_CANT_CHANGE')
    , @(0x0080, 'ENCRYPTED_TEXT_PWD_ALLOWED')
    , @(0x0200, 'NORMAL_ACCOUNT')
    , @(0x0800, 'INTERDOMAIN_TRUST_ACCOUNT')
    , @(0x1000, 'WORKSTATION_TRUST_ACCOUNT')
    , @(0x2000, 'SERVER_TRUST_ACCOUNT')
    , @(0x10000, 'DONT_EXPIRE_PASSWORD')
    , @(0x20000, 'MNS_LOGON_ACCOUNT')
    , @(0x40000, 'SMARTCARD_REQUIRED')
    , @(0x80000, 'TRUSTED_FOR_DELEGATION')
    , @(0x100000, 'NOT_DELEGATED')
    , @(0x200000, 'USE_DES_KEY_ONLY')
    , @(0x400000, 'DONT_REQ_PREAUTH')
    , @(0x800000, 'PASSWORD_EXPIRED')
    , @(0x1000000, 'TRUSTED_TO_AUTH_FOR_DELEGATION')
)

$RiskyUac = @{
    'PASSWD_NOTREQD'                 = 'UAC: password NOT required'
    'DONT_EXPIRE_PASSWORD'           = 'UAC: password never expires'
    'DONT_REQ_PREAUTH'               = 'UAC: Kerberos pre-auth disabled (AS-REP roastable)'
    'TRUSTED_FOR_DELEGATION'         = 'UAC: unconstrained delegation'
    'TRUSTED_TO_AUTH_FOR_DELEGATION' = 'UAC: protocol transition delegation'
    'USE_DES_KEY_ONLY'               = 'UAC: DES-only Kerberos keys'
    'ENCRYPTED_TEXT_PWD_ALLOWED'     = 'UAC: reversible password encryption'
    'SERVER_TRUST_ACCOUNT'           = 'UAC: SERVER_TRUST_ACCOUNT = a DOMAIN CONTROLLER account'
    'INTERDOMAIN_TRUST_ACCOUNT'      = 'UAC: interdomain trust account'
}

# Domain Admins/Schema/Enterprise/GPCO RIDs and built-in Administrators/Account Ops/Server Ops/Backup Ops
$PrivGroupRegex = '-(512|518|519|520)$|^S-1-5-32-(544|548|549|551)$'
$LocalPrivRegex = '^S-1-5-32-(544|548|549|551)$'

$MaxEventRetries = 3         # attempts before an unprocessable event gets a raw-field fallback report
$RecentAccountHours = 24     # "created recently" window used when correlating group adds
$WatchBatchSize = 20         # SIDs per XPath query (Windows event XPath rejects very long OR chains)
$DnsCacheMinutes = 60        # reverse-DNS cache lifetime

$script:DnsCache = @{}
$script:SidNameCache = @{}
$script:CreateTimes = @{}          # burst counters: key (one per account database) -> creation times
$script:RecentlyCreated = @{}      # SID -> time created
$script:RecentlyCreatedDn = @{}    # lower-case DN -> time created
$script:WatchSids = @{}            # SID -> @{Time; Creator; Computer; Name}  (first-logon tracking)
$script:SeenLogons = @{}           # key -> @{Sid; Time}; pruned when the SID leaves the watch list
$script:FailCount = @{}            # "phase|computer|recordId" -> failed processing attempts
$script:HasAD = [bool](Get-Module -ListAvailable -Name ActiveDirectory)
if ($script:HasAD) { Import-Module ActiveDirectory -ErrorAction SilentlyContinue }

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Get-EventData {
    param($Event)
    $data = @{}
    $xml = [xml]$Event.ToXml()
    foreach ($node in $xml.Event.EventData.Data) {
        $name = $node.GetAttribute('Name')
        if ($name) { $data[$name] = [string]$node.InnerText }
    }
    $data
}

function Convert-Uac {
    param([string]$Hex)
    if ([string]::IsNullOrWhiteSpace($Hex) -or $Hex -eq '-') { return @() }
    try { $v = [Convert]::ToInt64(($Hex.Trim() -replace '^0x', ''), 16) } catch { return @() }
    foreach ($f in $UacFlagList) { if (($v -band $f[0]) -ne 0) { $f[1] } }
}

function Get-LatestSecurityEvent {
    param([string]$Computer)
    Get-WinEvent -ComputerName $Computer -LogName Security -MaxEvents 1 -ErrorAction Stop
}

function Invoke-EventQuery {
    param([string]$Computer, [string]$XPath, [int]$MaxEvents = 0)
    try {
        if ($MaxEvents -gt 0) { @(Get-WinEvent -ComputerName $Computer -LogName Security -FilterXPath $XPath -MaxEvents $MaxEvents -ErrorAction Stop) }
        else { @(Get-WinEvent -ComputerName $Computer -LogName Security -FilterXPath $XPath -ErrorAction Stop) }
    }
    catch {
        if ($_.FullyQualifiedErrorId -notlike '*NoMatchingEventsFound*') { throw }
        @()
    }
}

function Test-IsLocalComputer {
    param([string]$Computer)
    ($Computer -in '.', 'localhost') -or ($Computer.Split('.')[0] -ieq $env:COMPUTERNAME)
}

function Invoke-OnComputer {
    param([string]$Computer, [scriptblock]$ScriptBlock, [object[]]$ArgumentList = @())
    # Only ever called with read-only query script blocks (Get-Local*).
    if (Test-IsLocalComputer $Computer) { & $ScriptBlock @ArgumentList }
    elseif ($DisableRemoteEnrichment) { throw 'Remote enrichment disabled' }
    else { Invoke-Command -ComputerName $Computer -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList -ErrorAction Stop }
}

function Resolve-SidName {
    param([string]$Sid)
    if ($script:SidNameCache.ContainsKey($Sid)) { return $script:SidNameCache[$Sid] }
    try { $n = (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value }
    catch { $n = $Sid }
    $script:SidNameCache[$Sid] = $n
    $n
}

function Resolve-SourceIP {
    param([string]$Address)
    $addr = ($Address -replace '^::ffff:', '').Trim()
    if ([string]::IsNullOrWhiteSpace($addr) -or $addr -in '-', '::1', '127.0.0.1') {
        return [pscustomobject]@{ Ip = $addr; IsRemote = $false; Hostname = $null; Label = 'Local session (no remote IP)' }
    }
    $dns = $null
    $cached = $script:DnsCache[$addr]
    if ($cached -and ((Get-Date) - $cached.Time).TotalMinutes -lt $DnsCacheMinutes) { $dns = $cached.Name }
    else {
        try { $dns = (Resolve-DnsName -Name $addr -Type PTR -QuickTimeout -ErrorAction Stop | Select-Object -First 1).NameHost } catch { $dns = $null }
        $script:DnsCache[$addr] = [pscustomobject]@{ Name = $dns; Time = Get-Date }
    }
    $label = if ($dns) { $dns } else { '(no reverse DNS record)' }
    [pscustomobject]@{ Ip = $addr; IsRemote = $true; Hostname = $dns; Label = $label }
}

function Get-LogonContext {
    # Finds the 4624 whose TargetLogonId equals the creator's SubjectLogonId.
    param([string]$Computer, [string]$LogonId)
    if ([string]::IsNullOrWhiteSpace($LogonId) -or $LogonId -eq '0x0') { return $null }
    $ms = [int64]$LogonLookbackHours * 3600000
    $xpath = "*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) <= $ms]] and EventData[Data[@Name='TargetLogonId']='$LogonId']]"
    try { $events = Invoke-EventQuery -Computer $Computer -XPath $xpath -MaxEvents 5 } catch { return $null }
    if ($events.Count -eq 0) { return $null }

    $parsed = foreach ($e in $events) {
        $l = Get-EventData $e
        [pscustomobject]@{
            Time            = $e.TimeCreated
            RecordId        = $e.RecordId
            LogonType       = [int]$l['LogonType']
            LogonTypeName   = $LogonTypes[[int]$l['LogonType']]
            IpAddress       = $l['IpAddress']
            IpPort          = $l['IpPort']
            WorkstationName = $l['WorkstationName']
            AuthPackage     = $l['AuthenticationPackageName']
            LogonProcess    = $l['LogonProcessName']
            ProcessName     = $l['ProcessName']
            ElevatedToken   = $l['ElevatedToken']
            LogonGuid       = $l['LogonGuid']
        }
    }
    $withIp = $parsed | Where-Object { $_.IpAddress -and $_.IpAddress -ne '-' } | Select-Object -First 1
    if ($withIp) { $withIp } else { $parsed | Select-Object -First 1 }
}

function Get-AdObjectInfo {
    param([string]$Sid)
    if (-not $script:HasAD -or [string]::IsNullOrWhiteSpace($Sid)) { return $null }
    try {
        Get-ADObject -Filter "objectSid -eq '$Sid'" -Properties distinguishedName, whenCreated, description, memberOf, userPrincipalName, objectClass -ErrorAction Stop |
            Select-Object -First 1
    }
    catch { $null }
}

function Get-LocalAccountInfo {
    # Local SAM account details + local group memberships (runs on the machine where the account lives).
    param([string]$Computer, [string]$Sid)
    $sb = {
        param($sid)
        $u = Get-LocalUser -SID $sid -ErrorAction Stop
        $names = @(); $sids = @()
        foreach ($g in Get-LocalGroup) {
            $hit = Get-LocalGroupMember -Group $g.Name -ErrorAction SilentlyContinue | Where-Object { $_.SID.Value -eq $sid }
            if ($hit) { $names += $g.Name; $sids += $g.SID.Value }
        }
        [pscustomobject]@{
            Name = $u.Name; Enabled = $u.Enabled; Description = $u.Description; PasswordRequired = $u.PasswordRequired
            LastLogon = $u.LastLogon; PasswordLastSet = $u.PasswordLastSet; GroupNames = $names; GroupSids = $sids
        }
    }
    try { Invoke-OnComputer -Computer $Computer -ScriptBlock $sb -ArgumentList @($Sid) } catch { $script:LastLookupError = $_.Exception.Message; $null }
}

function ConvertTo-SidString {
    # tokenGroups values can arrive as SecurityIdentifier objects (ActiveDirectory module) or as raw
    # byte[] (ADSI / DirectorySearcher). Handle both, plus plain SID strings. Returns $null if unparseable.
    param($Value)
    if ($null -eq $Value) { return $null }
    try {
        if ($Value -is [System.Security.Principal.SecurityIdentifier]) { return $Value.Value }
        if ($Value -is [byte[]]) { return (New-Object System.Security.Principal.SecurityIdentifier($Value, 0)).Value }
        $s = [string]$Value
        if ($s -match '^S-\d+-\d+') { return $s }
    }
    catch { }
    $null
}

function Get-CreatorInfo {
    # Who is the creator, really? Scope, status, nested group membership, privileged groups.
    param([string]$Sid, [string]$Computer, [bool]$IsLocal)
    $info = [pscustomobject]@{
        Scope = 'Unknown'; Resolved = $false; Enabled = $null; LastLogon = $null; PasswordLastSet = $null
        WhenCreated = $null; Description = $null; Groups = @(); PrivilegedGroups = @(); LookupNote = $null
    }
    if ($Sid -match '^S-1-5-(18|19|20)$') { $info.Scope = 'SYSTEM / service identity'; $info.Resolved = $true; return $info }

    if ($IsLocal) {
        $info.Scope = "LOCAL account on $Computer"
        $l = Get-LocalAccountInfo -Computer $Computer -Sid $Sid
        if ($l) {
            $info.Resolved = $true; $info.Enabled = $l.Enabled; $info.LastLogon = $l.LastLogon
            $info.PasswordLastSet = $l.PasswordLastSet; $info.Description = $l.Description
            $info.Groups = @($l.GroupNames)
            $priv = @()
            for ($i = 0; $i -lt @($l.GroupSids).Count; $i++) { if (@($l.GroupSids)[$i] -match $LocalPrivRegex) { $priv += @($l.GroupNames)[$i] } }
            $info.PrivilegedGroups = $priv
        }
        else { $info.LookupNote = $script:LastLookupError }
        return $info
    }

    if ($script:HasAD) {
        try {
            # Find out WHAT the creator is first (user, computer, managed service account), then use the matching
            # cmdlet. A computer account is not a "user" object, and a failed lookup is never hidden: the reason
            # ends up in LookupNote and is shown in the report.
            $obj = Get-ADObject -Filter "objectSid -eq '$Sid'" -Properties objectClass, distinguishedName -ErrorAction Stop | Select-Object -First 1
            if (-not $obj) { throw 'SID not found in this domain (other domain, or the object was deleted)' }
            $props = 'tokenGroups', 'Enabled', 'LastLogonDate', 'PasswordLastSet', 'whenCreated', 'Description'
            switch ($obj.objectClass) {
                'computer' {
                    $u = Get-ADComputer -Identity $obj.DistinguishedName -Properties $props -ErrorAction Stop
                    $info.Scope = 'DOMAIN COMPUTER account'
                }
                { $_ -in 'msDS-GroupManagedServiceAccount', 'msDS-ManagedServiceAccount' } {
                    $u = Get-ADServiceAccount -Identity $obj.DistinguishedName -Properties 'tokenGroups', 'Enabled', 'PasswordLastSet', 'whenCreated', 'Description' -ErrorAction Stop
                    $info.Scope = 'DOMAIN managed service account'
                }
                default {
                    $u = Get-ADUser -Identity $obj.DistinguishedName -Properties $props -ErrorAction Stop
                    $info.Scope = 'DOMAIN user account'
                }
            }
            $info.Enabled = $u.Enabled
            $info.LastLogon = $u.LastLogonDate; $info.PasswordLastSet = $u.PasswordLastSet
            $info.WhenCreated = $u.whenCreated; $info.Description = $u.Description
            $groups = @(); $priv = @(); $parsed = 0
            $tokens = @($u.tokenGroups)
            foreach ($g in $tokens) {
                $s = ConvertTo-SidString $g
                if (-not $s) { continue }
                $parsed++
                if ($s -match '^S-1-5-21-|^S-1-5-32-') {
                    $n = Resolve-SidName $s
                    $groups += $n
                    if ($s -match $PrivGroupRegex) { $priv += $n }
                }
            }
            if ($parsed -gt 0) { $info.Resolved = $true }
            else {
                # Every real account has token groups. Zero parsed means we could not READ them, so stay
                # "unresolved" rather than reporting a false "not in any privileged group".
                $t = if ($tokens.Count -gt 0 -and $null -ne $tokens[0]) { $tokens[0].GetType().FullName } else { 'no values' }
                $info.LookupNote = "tokenGroups gave no parseable SIDs (first value: $t); group data unavailable"
                if (-not $script:TokenWarned) { $script:TokenWarned = $true; Write-Warning $info.LookupNote }
            }
            $info.Groups = $groups; $info.PrivilegedGroups = $priv
        }
        catch { $info.LookupNote = $_.Exception.Message }
    }
    $info
}

function Write-Field {
    param([string]$Label, $Value, [string]$Color = 'White')
    if ($null -eq $Value -or "$Value" -eq '' -or "$Value" -eq '-') { $Value = '(none)' }
    Write-Host ('  {0,-24}: ' -f $Label) -NoNewline -ForegroundColor DarkGray
    Write-Host $Value -ForegroundColor $Color
}

function Write-Json {
    # Optional output only: does nothing unless -LogPath was supplied.
    # Appends to the file you named. Never creates folders and never changes permissions.
    param($Object)
    if ([string]::IsNullOrWhiteSpace($LogPath)) { return }
    try {
        # '{date}' in -LogPath becomes today's date: one file per day. Nothing is ever renamed or deleted.
        $path = $LogPath -replace '\{date\}', (Get-Date -Format 'yyyy-MM-dd')
        ($Object | ConvertTo-Json -Depth 6 -Compress) | Add-Content -Path $path -Encoding UTF8
    }
    catch { Write-Warning "Could not write to $LogPath : $($_.Exception.Message)" }
}

function Test-AuditPolicy {
    # Read-only (auditpol /get). Checks EACH monitored machine for the audit subcategories this script depends on.
    # Without them a machine produces no events, and the monitor would look healthy while being blind there.
    param([string[]]$Computers)
    $sb = {
        $subs = [ordered]@{
            'User Account Management'         = '{0CCE9235-69AE-11D9-BED3-505054503030}'
            'Computer Account Management'     = '{0CCE9236-69AE-11D9-BED3-505054503030}'
            'Security Group Management'       = '{0CCE9237-69AE-11D9-BED3-505054503030}'
            'Logon'                           = '{0CCE9215-69AE-11D9-BED3-505054503030}'
            'Kerberos Authentication Service' = '{0CCE9242-69AE-11D9-BED3-505054503030}'
        }
        $role = $null
        try { $role = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).DomainRole } catch { }
        $rows = foreach ($n in $subs.Keys) {
            $setting = 'could not read'
            try {
                $line = auditpol.exe /get "/subcategory:$($subs[$n])" /r 2>$null | Select-Object -Skip 1 | Where-Object { $_ } | Select-Object -First 1
                if ($line) { $setting = ($line | ConvertFrom-Csv -Header A, B, C, D, E, F).E }
            }
            catch { }
            [pscustomobject]@{ Name = $n; Setting = $setting }
        }
        [pscustomobject]@{ IsDC = ($null -ne $role -and $role -ge 4); Rows = @($rows) }
    }
    Write-Host 'Audit policy check (read-only, per machine):' -ForegroundColor Cyan
    $gaps = 0
    foreach ($c in $Computers) {
        $r = $null; $why = $null
        try { $r = Invoke-OnComputer -Computer $c -ScriptBlock $sb } catch { $why = $_.Exception.Message }
        if (-not $r) {
            $gaps++
            Write-Host ("  {0}: NOT CHECKED ({1}). Verify manually with: auditpol /get /category:*" -f $c, $(if ($why) { $why } else { 'no result' })) -ForegroundColor Yellow
            continue
        }
        Write-Host ("  {0}{1}" -f $c, $(if ($r.IsDC) { '  (domain controller)' } else { '' })) -ForegroundColor White
        foreach ($row in $r.Rows) {
            if ($row.Name -eq 'Kerberos Authentication Service' -and -not $r.IsDC) { continue }   # only DCs log 4768
            $ok = ($row.Setting -match 'Success')       # English wording; a localized OS may false-warn
            if (-not $ok) { $gaps++ }
            Write-Host ('    {0,-34} {1}' -f $row.Name, $row.Setting) -ForegroundColor $(if ($ok) { 'Green' } else { 'Yellow' })
        }
    }
    if ($gaps -gt 0) { Write-Host "  [!] $gaps audit gap(s): events behind those settings will be MISSING from this report." -ForegroundColor Yellow }
}

# ---------------------------------------------------------------------------
# Handler: account created (4720 / 4741)
# ---------------------------------------------------------------------------
function Invoke-AccountCreated {
    param($Event, [string]$Computer)

    $d = Get-EventData $Event
    $when = $Event.TimeCreated
    $local = $when.ToLocalTime()
    $isComputer = ($Event.Id -eq 4741)
    $kind = if ($isComputer) { 'COMPUTER ACCOUNT CREATED' } else { 'USER ACCOUNT CREATED' }

    # Local (SAM) vs domain scope: local accounts carry the machine name as their "domain"
    $machineShort = ([string]$Event.MachineName).Split('.')[0]
    $targetIsLocal = ($d['TargetDomainName'] -ieq $machineShort)
    $creatorIsLocal = ($d['SubjectDomainName'] -ieq $machineShort)

    $targetSam = if ($d['SamAccountName'] -and $d['SamAccountName'] -ne '-') { $d['SamAccountName'] } else { $d['TargetUserName'] }
    $creator = $d['SubjectUserName']
    $creatorFull = "$($d['SubjectDomainName'])\$creator"

    $logon = Get-LogonContext -Computer $Computer -LogonId $d['SubjectLogonId']
    $src = if ($logon) { Resolve-SourceIP $logon.IpAddress } else { $null }
    $uac = @(Convert-Uac $d['NewUacValue'])

    $ad = $null; $localInfo = $null; $memberOf = @()
    if ($targetIsLocal) {
        $localInfo = Get-LocalAccountInfo -Computer $Computer -Sid $d['TargetSid']
        if ($localInfo) { $memberOf = @($localInfo.GroupNames) }
    }
    else {
        $ad = Get-AdObjectInfo $d['TargetSid']
        if ($ad -and $ad.memberOf) { $memberOf = @($ad.memberOf | ForEach-Object { ($_ -split ',')[0] -replace '^CN=', '' }) }
    }
    $ci = Get-CreatorInfo -Sid $d['SubjectUserSid'] -Computer $Computer -IsLocal ([bool]$creatorIsLocal)
    $targetScope = if ($targetIsLocal) { "LOCAL account on $machineShort (SAM, not in AD)" } else { 'DOMAIN account (Active Directory)' }

    # --- Alerts ---
    $alerts = New-Object System.Collections.Generic.List[string]

    if ($targetIsLocal) { $alerts.Add("LOCAL account created on $machineShort (not in AD: bypasses domain policy and central management)") }
    if ($ExpectedCreators.Count -gt 0 -and $creator -notin $ExpectedCreators) { $alerts.Add("Creator '$creator' is not in ExpectedCreators") }
    if ($creator.EndsWith('$')) { $alerts.Add('Created by a computer/service identity (SYSTEM or machine account)') }
    if ($ci.Scope -like '*COMPUTER account*') { $alerts.Add("Creator is the COMPUTER account $creatorFull authenticating as itself (not a SYSTEM session): unusual, check for NTLM relay or delegation abuse") }
    if ($d['SubjectUserSid'] -match '-500$') { $alerts.Add('Created by a built-in Administrator (RID 500)') }
    if ($ci.Resolved -and $ci.Scope -notlike 'SYSTEM*' -and @($ci.PrivilegedGroups).Count -eq 0) {
        $alerts.Add('Creator is NOT in any privileged group (delegated rights, MachineAccountQuota, or compromised account?)')
    }
    if ($ci.Resolved -and $ci.Enabled -eq $false) { $alerts.Add('Creator account is DISABLED (stale session or ticket?)') }
    if (-not $logon) {
        $alerts.Add("No matching 4624 logon found for Logon ID $($d['SubjectLogonId']) in last $LogonLookbackHours h (SYSTEM session or older session)")
    }
    elseif ($src.IsRemote -and $TrustedSourceIPs.Count -gt 0 -and $src.Ip -notin $TrustedSourceIPs) {
        $alerts.Add("Source IP $($src.Ip) is not in TrustedSourceIPs")
    }
    if ($logon -and $logon.AuthPackage -eq 'NTLM' -and $logon.LogonType -eq 3) {
        $alerts.Add('Creator session authenticated with NTLM over the network (Kerberos expected for admin tools)')
    }
    if ($local.DayOfWeek -in 'Saturday', 'Sunday' -or $local.Hour -lt $BusinessStartHour -or $local.Hour -ge $BusinessEndHour) {
        $alerts.Add("Created outside business hours ($($local.ToString('ddd HH:mm')))")
    }
    foreach ($f in $uac) {
        if ($isComputer -and $f -eq 'PASSWD_NOTREQD') { continue }    # normal for a freshly joined machine account
        if ($RiskyUac.ContainsKey($f)) { $alerts.Add($RiskyUac[$f]) }
    }
    # A privileged primary group grants rights WITHOUT a group-add event (4728) - classic stealth trick
    $expectedPrimary = if ($isComputer) { @('515', '516') } else { @('513') }
    if ($d['PrimaryGroupId'] -and $d['PrimaryGroupId'] -notin $expectedPrimary) {
        $alerts.Add("PrimaryGroupId is $($d['PrimaryGroupId']) (expected $($expectedPrimary -join '/')): possible stealth group membership, no 4728 will fire")
    }
    if ($d['SidHistory'] -and $d['SidHistory'] -notin '-', '%%1793') { $alerts.Add("SidHistory is set: $($d['SidHistory'])") }
    if (-not $isComputer -and $targetSam.EndsWith('$')) { $alerts.Add("User account name ends with '$' (mimicking a machine account)") }
    if ($d['AllowedToDelegateTo'] -and $d['AllowedToDelegateTo'] -ne '-') { $alerts.Add("AllowedToDelegateTo set: $($d['AllowedToDelegateTo'])") }

    $burstKey = if ($targetIsLocal) { "LOCAL:$machineShort" } elseif ($isComputer) { 'DOMAIN:computer accounts' } else { 'DOMAIN:user accounts' }
    $burstCount = Update-BurstCounter -Key $burstKey -When $when
    if ($burstCount -ge $BurstThreshold) { $alerts.Add("$burstCount accounts created in '$burstKey' within $BurstWindowMinutes minutes") }

    # remember for correlation with later group-add and first-logon events (prune > 24h)
    $script:RecentlyCreated[$d['TargetSid']] = $when
    if ($ad -and $ad.DistinguishedName) { $script:RecentlyCreatedDn[$ad.DistinguishedName.ToLower()] = $when }
    # (expiry of these tables happens every poll in Invoke-Cleanup)
    if (-not $ExcludeFirstLogonTracking) {
        $script:WatchSids[$d['TargetSid']] = [pscustomobject]@{ Time = $when; Creator = $creatorFull; Computer = $Computer; Name = $targetSam }
    }

    # --- Console report ---
    $barColor = if ($alerts.Count -gt 0) { 'Red' } else { 'Green' }
    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor $barColor
    Write-Host ("[{0}] {1}   (log source: {2}, RecordId {3})" -f $local.ToString('yyyy-MM-dd HH:mm:ss'), $kind, $Computer, $Event.RecordId) -ForegroundColor $barColor
    Write-Host ('-' * 78) -ForegroundColor $barColor

    Write-Host ' NEW ACCOUNT' -ForegroundColor Cyan
    Write-Field 'SamAccountName' $targetSam 'Yellow'
    Write-Field 'Scope' $targetScope $(if ($targetIsLocal) { 'Red' } else { 'White' })
    Write-Field 'Domain / Machine' $d['TargetDomainName']
    Write-Field 'SID' $d['TargetSid']
    Write-Field 'UPN' $d['UserPrincipalName']
    Write-Field 'Display name' $d['DisplayName']
    if ($isComputer) {
        Write-Field 'DNS host name' $d['DnsHostName']
        Write-Field 'SPNs' $d['ServicePrincipalNames']
    }
    $dnText = if ($targetIsLocal) { '(local SAM account - no DN)' } elseif ($ad) { $ad.DistinguishedName } else { '(AD lookup unavailable)' }
    Write-Field 'Distinguished name' $dnText
    if ($localInfo) {
        Write-Field 'Enabled' $localInfo.Enabled
        Write-Field 'Password required' $localInfo.PasswordRequired
        Write-Field 'Description' $localInfo.Description
    }
    Write-Field 'UAC (new value)' ("{0}  {1}" -f $d['NewUacValue'], ($uac -join ', '))
    Write-Field 'Primary group ID' $d['PrimaryGroupId']
    Write-Field 'Password last set' $d['PasswordLastSet']
    Write-Field 'Account expires' $d['AccountExpires']
    Write-Field 'Home dir / drive' ("{0} {1}" -f $d['HomeDirectory'], $d['HomePath'])
    Write-Field 'Logon script' $d['ScriptPath']
    Write-Field 'Profile path' $d['ProfilePath']
    Write-Field 'Allowed workstations' $d['UserWorkstations']
    Write-Field 'SID history' $d['SidHistory']
    Write-Field 'Group membership (now)' $(if ($memberOf.Count) { $memberOf -join ', ' } else { '(none yet - may be added moments later)' })

    Write-Host ' CREATED BY' -ForegroundColor Cyan
    Write-Field 'Account' $creatorFull 'Yellow'
    Write-Field 'Scope' $ci.Scope
    if ($ci.LookupNote) { Write-Field 'Lookup note' $ci.LookupNote 'Yellow' }
    Write-Field 'SID' $d['SubjectUserSid']
    Write-Field 'Logon ID (4720 Subject)' $d['SubjectLogonId'] 'Yellow'
    Write-Field 'Enabled' $ci.Enabled
    Write-Field 'Account created' $ci.WhenCreated
    Write-Field 'Password last set' $ci.PasswordLastSet
    Write-Field 'Last logon (approx.)' $ci.LastLogon
    Write-Field 'Description' $ci.Description
    Write-Field 'Privileged groups' $(if (-not $ci.Resolved) { '(lookup unavailable)' } elseif (@($ci.PrivilegedGroups).Count) { @($ci.PrivilegedGroups) -join ', ' } else { 'none' }) $(if (@($ci.PrivilegedGroups).Count) { 'Yellow' } else { 'White' })
    Write-Field 'All groups (nested)' $(if (@($ci.Groups).Count) { @($ci.Groups) -join ', ' } else { '(unavailable)' })
    Write-Field 'Privileges used' $d['PrivilegeList']

    Write-Host ' CREATOR SESSION (matched 4624 by Logon ID)' -ForegroundColor Cyan
    if ($logon) {
        Write-Field 'Source IP' $src.Ip 'Yellow'
        Write-Field 'Source host' $src.Label
        Write-Field 'Source port' $logon.IpPort
        Write-Field 'Workstation name' $logon.WorkstationName
        Write-Field 'Logon type' ("{0} - {1}" -f $logon.LogonType, $logon.LogonTypeName)
        Write-Field 'Auth package' $logon.AuthPackage
        Write-Field 'Logon process' $logon.LogonProcess
        Write-Field 'Logon time' $logon.Time.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss')
        Write-Field 'Logon event RecordId' $logon.RecordId
        Write-Field 'Elevated token' $logon.ElevatedToken
        Write-Field 'Logon GUID' $logon.LogonGuid
    }
    else { Write-Field 'Logon' 'No matching 4624 found' 'Yellow' }

    if ($alerts.Count -gt 0) {
        Write-Host ' ALERTS' -ForegroundColor Red
        foreach ($a in $alerts) { Write-Host "  [!] $a" -ForegroundColor Red }
    }
    Write-Host ('=' * 78) -ForegroundColor $barColor

    # --- JSON log ---
    Write-Json ([ordered]@{
            time         = $when.ToUniversalTime().ToString('o')
            event        = $Event.Id
            kind         = $kind
            source       = $Computer
            recordId     = $Event.RecordId
            alerts       = @($alerts)
            target       = [ordered]@{
                scope = $targetScope; sam = $targetSam; domain = $d['TargetDomainName']; sid = $d['TargetSid']; upn = $d['UserPrincipalName']
                displayName = $d['DisplayName']; dn = $(if ($ad) { $ad.DistinguishedName } else { $null })
                uacValue = $d['NewUacValue']; uacFlags = $uac; primaryGroupId = $d['PrimaryGroupId']
                passwordLastSet = $d['PasswordLastSet']; accountExpires = $d['AccountExpires']
                sidHistory = $d['SidHistory']; memberOf = $memberOf; workstations = $d['UserWorkstations']
                homeDirectory = $d['HomeDirectory']; scriptPath = $d['ScriptPath']; profilePath = $d['ProfilePath']
            }
            creator      = [ordered]@{
                account = $creatorFull; sid = $d['SubjectUserSid']; logonId = $d['SubjectLogonId']; scope = $ci.Scope; lookupNote = $ci.LookupNote
                enabled = $ci.Enabled; whenCreated = $ci.WhenCreated; passwordLastSet = $ci.PasswordLastSet; lastLogon = $ci.LastLogon
                privilegedGroups = @($ci.PrivilegedGroups); groups = @($ci.Groups); privileges = $d['PrivilegeList']
            }
            creatorLogon = if ($logon) {
                [ordered]@{
                    ip = $src.Ip; hostLabel = $src.Label; dns = $src.Hostname; port = $logon.IpPort
                    workstation = $logon.WorkstationName; logonType = $logon.LogonType; logonTypeName = $logon.LogonTypeName
                    authPackage = $logon.AuthPackage; logonProcess = $logon.LogonProcess
                    logonTime = $logon.Time.ToUniversalTime().ToString('o'); logonRecordId = $logon.RecordId
                }
            } else { $null }
        })
}

# ---------------------------------------------------------------------------
# Handler: related events (4722 / 4724 / 4728 / 4732 / 4756)
# ---------------------------------------------------------------------------
function Invoke-RelatedEvent {
    param($Event, [string]$Computer)

    $d = Get-EventData $Event
    $local = $Event.TimeCreated.ToLocalTime()
    $actor = "$($d['SubjectDomainName'])\$($d['SubjectUserName'])"
    $sid = $d['TargetSid']; $msg = ''; $isPrivGroup = $false

    switch ($Event.Id) {
        4722 { $msg = "Account ENABLED: $($d['TargetDomainName'])\$($d['TargetUserName'])" }
        4724 { $msg = "Password RESET attempt on: $($d['TargetDomainName'])\$($d['TargetUserName'])" }
        { $_ -in 4728, 4732, 4756 } {
            $sid = $d['MemberSid']
            $isPrivGroup = ($d['TargetSid'] -match $PrivGroupRegex)
            $msg = "Member added to group '$($d['TargetUserName'])': $($d['MemberName'])  [$sid]"
        }
    }

    $mn = [string]$d['MemberName']
    $createdAt = Get-RecentCreationTime -Sid $sid -MemberDn $mn -At $Event.TimeCreated
    $isNew = [bool]$createdAt
    $ageText = if ($createdAt) { '{0:N1} h ago' -f ($Event.TimeCreated - $createdAt).TotalHours } else { '' }
    $color = if ($isPrivGroup) { 'Red' } else { 'Yellow' }

    Write-Host ''
    Write-Host ("[{0}] RELATED EVENT {1} on {2}: {3}" -f $local.ToString('yyyy-MM-dd HH:mm:ss'), $Event.Id, $Computer, $msg) -ForegroundColor $color
    Write-Host ("    Actor: {0}  (Logon ID {1})" -f $actor, $d['SubjectLogonId']) -ForegroundColor $color
    if ($isPrivGroup) { Write-Host '    [!] Target group is PRIVILEGED' -ForegroundColor Red }
    if ($isNew) { Write-Host ("    [!] This account was created {0} (inside the {1} h window, while this monitor was running)" -f $ageText, $RecentAccountHours) -ForegroundColor Red }
    if ($isNew -and $isPrivGroup) { Write-Host '    [!!] NEW ACCOUNT ADDED TO A PRIVILEGED GROUP' -ForegroundColor Red }

    Write-Json ([ordered]@{
            time = $Event.TimeCreated.ToUniversalTime().ToString('o'); event = $Event.Id; kind = 'RELATED'
            source = $Computer; recordId = $Event.RecordId; message = $msg; actor = $actor
            actorLogonId = $d['SubjectLogonId']; privilegedGroup = $isPrivGroup; recentlyCreatedAccount = [bool]$isNew
        })
}

# ---------------------------------------------------------------------------
# First-logon tracking for newly created accounts (4624 + 4768)
# ---------------------------------------------------------------------------
function Get-WatchEvents {
    param([string]$Computer, [long]$From, [long]$To)
    if ($script:WatchSids.Count -eq 0) { return @() }
    # EVERY watched SID is queried for EVERY window, in batches. (Rotating through batches across polls
    # would be wrong: the checkpoint moves on each poll, so a skipped batch would lose that window's logons.)
    # Any query failure throws on purpose: the caller then leaves the watch checkpoint untouched and the
    # whole window is retried next poll. Nothing is processed until all batches have succeeded.
    $all = @($script:WatchSids.Keys)
    $out = @()
    for ($i = 0; $i -lt $all.Count; $i += $WatchBatchSize) {
        $last = [Math]::Min($i + $WatchBatchSize, $all.Count) - 1
        $chunk = @($all[$i..$last])
        $c4624 = ($chunk | ForEach-Object { "Data[@Name='TargetUserSid']='$_'" }) -join ' or '
        $c4768 = ($chunk | ForEach-Object { "Data[@Name='TargetSid']='$_'" }) -join ' or '
        $out += Invoke-EventQuery -Computer $Computer -XPath "*[System[(EventID=4624) and EventRecordID>$From and EventRecordID<=$To] and EventData[$c4624]]"
        $out += Invoke-EventQuery -Computer $Computer -XPath "*[System[(EventID=4768) and EventRecordID>$From and EventRecordID<=$To] and EventData[$c4768]]"
    }
    $out | Sort-Object RecordId
}

function Invoke-FirstLogon {
    param($Event, [string]$Computer)
    $d = Get-EventData $Event
    if ($Event.Id -eq 4624) {
        $sid = $d['TargetUserSid']; $how = 'Logon (4624)'
        $detail = "type {0} - {1}, {2}" -f $d['LogonType'], $LogonTypes[[int]$d['LogonType']], $d['AuthenticationPackageName']
        $failed = $false
    }
    else {
        $sid = $d['TargetSid']; $how = 'Kerberos TGT request (4768)'
        $detail = "status $($d['Status'])"
        $failed = ($d['Status'] -ne '0x0')
    }
    $w = $script:WatchSids[$sid]
    if (-not $w) { return }

    $src = Resolve-SourceIP $d['IpAddress']
    if (-not $ReportAllNewAccountLogons) {
        # Default: show only the first-seen combination of machine / account / source IP / event / logon type.
        # (Use -ReportAllNewAccountLogons to see every logon; nothing is deduplicated or stored in that mode.)
        $key = "$Computer|$sid|$($src.Ip)|$($Event.Id)|$($d['LogonType'])|$($d['Status'])"
        if ($script:SeenLogons.ContainsKey($key)) { return }
        $script:SeenLogons[$key] = [pscustomobject]@{ Sid = $sid; Time = $Event.TimeCreated }
    }

    $mins = [int]($Event.TimeCreated - $w.Time).TotalMinutes
    $color = if ($failed) { 'Red' } else { 'Yellow' }
    Write-Host ''
    Write-Host ("[{0}] NEW-ACCOUNT ACTIVITY on {1}: {2}" -f $Event.TimeCreated.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss'), $Computer, $how) -ForegroundColor $color
    Write-Host ("    Account : {0}  (created {1} min ago by {2})" -f $w.Name, $mins, $w.Creator) -ForegroundColor $color
    Write-Host ("    From    : {0}  {1}" -f $src.Ip, $src.Label) -ForegroundColor $color
    Write-Host ("    Detail  : {0}   workstation: {1}" -f $detail, $d['WorkstationName']) -ForegroundColor $color

    Write-Json ([ordered]@{
            time = $Event.TimeCreated.ToUniversalTime().ToString('o'); event = $Event.Id; kind = 'NEW_ACCOUNT_ACTIVITY'
            source = $Computer; recordId = $Event.RecordId; account = $w.Name; sid = $sid; minutesSinceCreation = $mins
            createdBy = $w.Creator; ip = $src.Ip; hostLabel = $src.Label; detail = $detail; workstation = $d['WorkstationName']
        })
}

# ---------------------------------------------------------------------------
# Tracking-table maintenance and checkpoint-safe event processing
# ---------------------------------------------------------------------------
function Update-BurstCounter {
    # Burst detection is kept per ACCOUNT DATABASE and never mixed: all domain user accounts share one counter,
    # domain computer accounts another (mass domain joins are normal), and each machine's local accounts have
    # their own. Returns how many creations that counter holds inside the window.
    param([string]$Key, [datetime]$When)
    $prev = $script:CreateTimes[$Key]
    if ($null -eq $prev) { $prev = @() }
    $times = @($prev | Where-Object { $_ -ge $When.AddMinutes(-$BurstWindowMinutes) -and $_ -ne $When }) + $When
    $script:CreateTimes[$Key] = $times
    $times.Count
}

function Get-LogDiscontinuity {
    # Proves we are still reading the SAME log we read last poll. At the end of every poll we remember the newest
    # record (id + timestamp). Next poll we look that exact record up again (a cheap point query: it sits at the
    # newest end of the log). If it is gone, or the id now holds a different event, the log was cleared.
    # Returns a reason string, or $null when everything is intact.
    param([string]$Computer, $Tail, [long]$Newest, [long]$Position)
    if ($Newest -lt $Position) { return "newest RecordId $Newest is lower than our position $Position" }
    if ($null -eq $Tail) { return $null }
    $probe = @(Invoke-EventQuery -Computer $Computer -XPath "*[System[EventRecordID=$($Tail.RecordId)]]" -MaxEvents 1)
    if ($probe.Count -eq 0) { return "record $($Tail.RecordId), seen on the previous poll, no longer exists" }
    if ($probe[0].TimeCreated.Ticks -ne $Tail.Ticks) { return "record $($Tail.RecordId) now holds a different event than on the previous poll" }
    $null
}

function Get-RecentCreationTime {
    # Returns when the account was created if that was within $RecentAccountHours before $At, else $null.
    param([string]$Sid, [string]$MemberDn, [datetime]$At)
    $t = $null
    if ($Sid -and $script:RecentlyCreated.ContainsKey($Sid)) { $t = $script:RecentlyCreated[$Sid] }
    elseif ($MemberDn -and $script:RecentlyCreatedDn.ContainsKey($MemberDn.ToLower())) { $t = $script:RecentlyCreatedDn[$MemberDn.ToLower()] }
    if ($t -and ($At - $t).TotalHours -le $RecentAccountHours) { return $t }
    $null
}

function Invoke-Cleanup {
    # Runs EVERY poll (not only when something is created): expires in-memory tracking so nothing
    # grows without bound or goes stale on a monitor that runs for weeks.
    $now = Get-Date
    foreach ($k in @($script:RecentlyCreated.Keys)) { if (($now - $script:RecentlyCreated[$k]).TotalHours -gt $RecentAccountHours) { $script:RecentlyCreated.Remove($k) } }
    foreach ($k in @($script:RecentlyCreatedDn.Keys)) { if (($now - $script:RecentlyCreatedDn[$k]).TotalHours -gt $RecentAccountHours) { $script:RecentlyCreatedDn.Remove($k) } }
    foreach ($k in @($script:WatchSids.Keys)) { if (($now - $script:WatchSids[$k].Time).TotalHours -gt $FirstLogonWatchHours) { $script:WatchSids.Remove($k) } }
    foreach ($k in @($script:SeenLogons.Keys)) { if (-not $script:WatchSids.ContainsKey($script:SeenLogons[$k].Sid)) { $script:SeenLogons.Remove($k) } }
    foreach ($k in @($script:DnsCache.Keys)) { if (($now - $script:DnsCache[$k].Time).TotalMinutes -ge $DnsCacheMinutes) { $script:DnsCache.Remove($k) } }
    foreach ($k in @($script:CreateTimes.Keys)) {
        $kept = @($script:CreateTimes[$k] | Where-Object { ($now - $_).TotalMinutes -le $BurstWindowMinutes })
        if ($kept.Count -gt 0) { $script:CreateTimes[$k] = $kept } else { $script:CreateTimes.Remove($k) }
    }
}

function Write-FallbackReport {
    # Last resort when an event cannot be processed normally: print its raw fields so the information is never lost.
    param($Event, [string]$Computer, $ErrorRecord, [string]$Phase)
    $d = @{}
    try { $d = Get-EventData $Event } catch { }
    Write-Host ''
    Write-Host ("[{0}] !! EVENT {1} (RecordId {2} on {3}) COULD NOT BE FULLY PROCESSED - RAW FIELDS FOLLOW" -f $Event.TimeCreated.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss'), $Event.Id, $Event.RecordId, $Computer) -ForegroundColor Red
    Write-Host ("    Error: {0}" -f $ErrorRecord.Exception.Message) -ForegroundColor Red
    foreach ($k in ($d.Keys | Sort-Object)) { Write-Host ("    {0} = {1}" -f $k, $d[$k]) -ForegroundColor Red }
    Write-Json ([ordered]@{
            time = $Event.TimeCreated.ToUniversalTime().ToString('o'); event = $Event.Id; kind = 'EVENT_PROCESSING_FAILED'
            phase = $Phase; source = $Computer; recordId = $Event.RecordId; error = $ErrorRecord.Exception.Message; fields = $d
        })
}

function Invoke-EventBatch {
    # Handles events in RecordId order and returns the NEW CHECKPOINT.
    #   success -> the checkpoint moves past the event
    #   failure -> the checkpoint stays just BEFORE the failed event so it is retried next poll; later events
    #              are untouched, so nothing is ever reported twice
    #   after $MaxEventRetries failures -> a raw-field fallback report is printed/logged and the event is
    #              skipped, so one malformed event can never block the monitor forever
    param([string]$Computer, [object[]]$Events, [long]$Upper, [string]$Phase, [scriptblock]$Handler)
    foreach ($e in $Events) {
        if ($null -eq $e) { continue }
        $key = "$Phase|$Computer|$($e.RecordId)"
        try {
            $null = & $Handler $e $Computer
            $script:FailCount.Remove($key)
        }
        catch {
            $script:FailCount[$key] = 1 + [int]$script:FailCount[$key]
            if ($script:FailCount[$key] -lt $MaxEventRetries) {
                Write-Warning ("Event {0} (RecordId {1}) on {2} failed: {3}  -- will retry ({4}/{5})" -f $e.Id, $e.RecordId, $Computer, $_.Exception.Message, $script:FailCount[$key], $MaxEventRetries)
                return [long]($e.RecordId - 1)
            }
            $null = Write-FallbackReport -Event $e -Computer $Computer -ErrorRecord $_ -Phase $Phase
            $script:FailCount.Remove($key)
        }
    }
    $Upper
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
$ids = @(4720)
if (-not $ExcludeComputerAccounts) { $ids += 4741 }
if (-not $ExcludeRelated) { $ids += 4722, 4724, 4728, 4732, 4756 }
$idFilter = ($ids | ForEach-Object { "EventID=$_" }) -join ' or '

Write-Host ('=' * 78) -ForegroundColor Cyan
Write-Host ' Account creation monitor' -ForegroundColor Cyan
Write-Host ('  Machines     : {0}' -f ($ComputerName -join ', '))
Write-Host ('  Event IDs    : {0}  (+4624 correlation{1})' -f ($ids -join ', '), $(if ($ExcludeFirstLogonTracking) { '' } else { ', 4624/4768 first-logon tracking' }))
Write-Host ('  Poll         : every {0}s   Logon lookback: {1}h' -f $PollSeconds, $LogonLookbackHours)
Write-Host ('  New-acct logons: {0}' -f $(if ($ExcludeFirstLogonTracking) { 'off' } elseif ($ReportAllNewAccountLogons) { 'every logon reported' } else { 'first-seen (machine, account, source IP, logon type) only' }))
Write-Host '  Mode         : READ-ONLY (reports only, changes nothing on any system)' -ForegroundColor Green
Write-Host ('  JSON log     : {0}' -f $(if ($LogPath) { $LogPath } else { 'disabled (console output only)' }))
Write-Host ('  Remote query : {0}' -f $(if ($DisableRemoteEnrichment) { 'disabled' } else { 'read-only WinRM queries for local-account details' }))
Write-Host ('  AD module    : {0}' -f $(if ($script:HasAD) { 'available' } else { 'NOT available (domain account enrichment disabled)' }))
Write-Host '  Press Ctrl+C to stop.'
Write-Host ('=' * 78) -ForegroundColor Cyan
Test-AuditPolicy -Computers $ComputerName

# Two independent checkpoints per machine (highest RecordId fully handled):
#   $mainPos  - account / related events
#   $watchPos - first-logon tracking
# Keeping them separate means a failure in one phase can never cause the other phase to skip OR repeat events.
# $tail remembers the newest record (id + timestamp) of the previous poll, to prove the log was not cleared.
$mainPos = @{}
$watchPos = @{}
$tail = @{}
foreach ($c in $ComputerName) {
    try {
        $t = Get-LatestSecurityEvent $c
        $mainPos[$c] = $t.RecordId; $watchPos[$c] = $t.RecordId
        $tail[$c] = [pscustomobject]@{ RecordId = $t.RecordId; Ticks = $t.TimeCreated.Ticks }
        Write-Host ("Watching {0} from RecordId {1}" -f $c, $t.RecordId) -ForegroundColor Green
    }
    catch {
        # Unreachable at startup: do NOT start from 0 (that would replay the whole old log later).
        # Start from "now" on the first successful poll instead.
        Write-Warning "Cannot read Security log on $c yet ($($_.Exception.Message)). Will begin watching it once reachable."
        $mainPos[$c] = $null; $watchPos[$c] = $null; $tail[$c] = $null
    }
}

try {
    while ($true) {
        Invoke-Cleanup     # expire tracking tables every poll

        foreach ($c in $ComputerName) {
            try {
                $latest = Get-LatestSecurityEvent $c
                $newest = $latest.RecordId

                if ($null -eq $mainPos[$c]) {
                    $mainPos[$c] = $newest; $watchPos[$c] = $newest
                    $tail[$c] = [pscustomobject]@{ RecordId = $newest; Ticks = $latest.TimeCreated.Ticks }
                    Write-Host ("Now watching {0} from RecordId {1}" -f $c, $newest) -ForegroundColor Green
                    continue
                }

                # Log-clear handling. Clearing deletes every record, so whatever is in the log now is NEW
                # (never processed): re-reading from the start cannot duplicate a report. The real risk is the
                # opposite, silently SKIPPING events (e.g. new records already passed our old position), and
                # that is what the continuity check catches. Events destroyed by the clear are unrecoverable.
                $why = Get-LogDiscontinuity -Computer $c -Tail $tail[$c] -Newest $newest -Position $mainPos[$c]
                if ($why) {
                    Write-Host "[!] Security log on $c is no longer the log we were reading: $why." -ForegroundColor Red
                    Write-Host "    Probably CLEARED. Events written before the clear are gone and cannot be recovered by this monitor." -ForegroundColor Red
                    Write-Host "    Re-reading the current log from its start (everything in it is newer than the clear)." -ForegroundColor Red
                    Write-Json ([ordered]@{ time = (Get-Date).ToUniversalTime().ToString('o'); kind = 'LOG_DISCONTINUITY'; source = $c; reason = $why })
                    $mainPos[$c] = 0; $watchPos[$c] = 0
                }

                # Phase 1: account creation and related events
                if ($newest -gt $mainPos[$c]) {
                    $xpath = "*[System[($idFilter) and EventRecordID>$($mainPos[$c]) and EventRecordID<=$newest]]"
                    $events = @(Invoke-EventQuery -Computer $c -XPath $xpath | Sort-Object RecordId)
                    $mainPos[$c] = Invoke-EventBatch -Computer $c -Events $events -Upper $newest -Phase 'main' -Handler {
                        param($ev, $cn)
                        if ($ev.Id -in 4720, 4741) { Invoke-AccountCreated -Event $ev -Computer $cn }
                        else { Invoke-RelatedEvent -Event $ev -Computer $cn }
                    }
                }

                # Phase 2: first logons of newly created accounts (4624 / 4768)
                if (-not $ExcludeFirstLogonTracking -and $newest -gt $watchPos[$c]) {
                    $wev = @(Get-WatchEvents -Computer $c -From $watchPos[$c] -To $newest)   # throws on failure -> window retried
                    $watchPos[$c] = Invoke-EventBatch -Computer $c -Events $wev -Upper $newest -Phase 'watch' -Handler {
                        param($ev, $cn)
                        Invoke-FirstLogon -Event $ev -Computer $cn
                    }
                }

                $tail[$c] = [pscustomobject]@{ RecordId = $newest; Ticks = $latest.TimeCreated.Ticks }
            }
            catch { Write-Warning "Poll error on $c : $($_.Exception.Message)" }
        }
        Start-Sleep -Seconds $PollSeconds
    }
}
finally {
    Write-Host "`nMonitor stopped." -ForegroundColor Cyan
}
