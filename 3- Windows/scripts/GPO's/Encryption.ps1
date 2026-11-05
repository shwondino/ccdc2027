<#
.SYNOPSIS
    Creates a GPO called "encryption", links it, and enforces strong Kerberos / LDAP / NTLM / SMB settings.

.DESCRIPTION
    Run from an elevated Windows PowerShell 5.1 prompt on a DC (or a host with RSAT: GPMC + AD PowerShell)
    as a Domain Admin. Paste it into the console or save it as a .ps1: there are no settings to edit.

    The script asks whether to run a dry run or make real changes, and for each setting whether to
    turn it on (Enter or y = on, n = leave it alone). The GPO is always linked at the domain root.

    Settings managed by the GPO:
      - Disable SMB1 (server): Disables the legacy SMBv1 protocol on Windows file servers.
      - Kerberos AES only: Restricts Kerberos encryption to AES128 and AES256, disabling RC4 and DES.
      - LDAP server signing required (DC): Requires LDAP clients to sign connections to domain controllers.
      - LDAP client signing required: Requires this computer to sign outgoing LDAP connections.
      - LDAP channel binding always (DC): Requires channel binding for LDAPS connections to domain controllers.
      - NTLMv2 only: Prevents LM and NTLMv1 authentication. Answering n applies compatibility level 3 instead.
      - SMB signing required (server): Requires incoming SMB connections to use signing.
      - SMB signing required (client): Requires outgoing SMB connections to use signing.

    Before each setting question, the script shows what AD says could break.
    An answer of n leaves the setting unchanged, except LmCompatibilityLevel, where n applies level 3.
    DC-specific settings are additionally linked to the Domain Controllers OU when enabled
#>
$ErrorActionPreference = 'Stop'
$GpoName = 'encryption'
$script:Results = New-Object System.Collections.Generic.List[object]
$script:Ctx     = @{ ModulesOk = $false; DomainOk = $false; GpoGuid = $null; GpoPlanned = $false; GpoExisted = $false
                     LinkDN = $null; DcOuDN = $null; DomainMode = '' }
6
# Any unexpected error outside a block: show it
trap {
    Write-Host "`nUNHANDLED ERROR: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
    break
}

# Log goes next to the script (or the temp folder when pasted)
$LogDir  = if ($PSScriptRoot) { $PSScriptRoot } else { [IO.Path]::GetTempPath() }
$LogFile = Join-Path $LogDir ("Encryption-GPO-{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
try { Start-Transcript -Path $LogFile | Out-Null } catch { $LogFile = $null; Write-Warning "Could not start transcript: $($_.Exception.Message)" }

# =====================================================================================
# FRAMEWORK
# =====================================================================================
function Invoke-Block {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Name,
        [scriptblock]$Prereq,    # returns $null if OK, or a string explaining why it can't run
        [Parameter(Mandatory)][scriptblock]$Action
    )
    Write-Host ("`n=== [{0}] {1} ===" -f $Id, $Name) -ForegroundColor Cyan
    $status = 'OK'; $detail = ''
    try {
        $reason = $null
        if ($Prereq) {
            try   { $reason = & $Prereq }
            catch { $reason = "Prereq check errored: $($_.Exception.Message)" }
        }
        if ($reason)       { $status = 'SKIPPED'; $detail = [string]($reason | Select-Object -Last 1) }
        elseif ($DryRun)   { $status = 'DRYRUN';  $detail = 'Dry run, no changes made' }
        else {
            $out = & $Action
            if ($out) { $detail = [string]($out | Select-Object -Last 1) }
        }
    }
    catch { $status = 'FAILED'; $detail = $_.Exception.Message }
    $colour = @{ OK='Green'; SKIPPED='Yellow'; FAILED='Red'; DRYRUN='Gray' }[$status]
    Write-Host ("[{0}] {1}" -f $status, $detail) -ForegroundColor $colour
    $script:Results.Add([pscustomobject]@{ Block = $Id; Name = $Name; Status = $status; Detail = $detail })
}

function Confirm-Yes {
    # Enter, y or yes (any case) = yes. n or no = no. No interactive console = no.
    param([string]$Question, [bool]$DefaultYes = $true)
    $redirected = $false
    try { $redirected = [Console]::IsInputRedirected } catch { }
    if ($redirected) { return $false }
    $hint = if ($DefaultYes) { '[Y/n] (Enter = yes)' } else { '[y/N] (Enter = no)' }
    for ($i = 0; $i -lt 3; $i++) {
        $r = ''
        try { $r = ([string](Read-Host "$Question $hint")).Trim() } catch { return $false }
        if ($r -eq '') { return $DefaultYes }
        if ($r -imatch '^(y|yes)$') { return $true }
        if ($r -imatch '^(n|no)$') { return $false }
        Write-Host 'Please answer y or n.' -ForegroundColor Yellow
    }
    $false
}

function Test-GpoReady {
    if (-not $script:Ctx.ModulesOk) { return 'GroupPolicy / ActiveDirectory modules not available (see B02)' }
    if (-not $script:Ctx.DomainOk)  { return 'Domain context / permissions check did not pass (see B03)' }
    if (-not $script:Ctx.GpoGuid) {
        if ($DryRun -and $script:Ctx.GpoPlanned) { return $null }
        return "GPO '$GpoName' does not exist and could not be created (see B04)"
    }
    return $null
}

function Get-GpoSysvolPath {
    param([guid]$Guid)
    "\\{0}\SYSVOL\{1}\Policies\{2}" -f $script:Ctx.Pdc, $script:Ctx.DnsRoot, $Guid.ToString('B').ToUpper()
}

function Set-GpoReg {
    param([string]$Key, [string]$Name, [ValidateSet('DWord','String')][string]$Type, $Value)
    Set-GPRegistryValue -Guid $script:Ctx.GpoGuid -Domain $script:Ctx.DnsRoot -Server $script:Ctx.Pdc `
        -Key $Key -ValueName $Name -Type $Type -Value $Value | Out-Null
    $back = Get-GPRegistryValue -Guid $script:Ctx.GpoGuid -Domain $script:Ctx.DnsRoot -Server $script:Ctx.Pdc `
        -Key $Key -ValueName $Name
    if ("$($back.Value)" -ne "$Value") { throw "Read-back mismatch for $Key\$Name (got '$($back.Value)', expected '$Value')" }
}

function Step-GpoVersion {
    # bump machine version in AD and GPT.INI so clients re-process file-based settings
    param([guid]$Guid)
    $b   = $Guid.ToString('B').ToUpper()
    $dn  = "CN=$b,CN=Policies,CN=System,$($script:Ctx.DomainDN)"
    $obj = Get-ADObject -Identity $dn -Server $script:Ctx.Pdc -Properties versionNumber
    $new = [int]$obj.versionNumber + 1
    Set-ADObject -Identity $dn -Server $script:Ctx.Pdc -Replace @{ versionNumber = $new }
    $ini = Join-Path (Get-GpoSysvolPath $Guid) 'GPT.INI'
    if (Test-Path -LiteralPath $ini) {
        $lines = @(Get-Content -LiteralPath $ini)
        if ($lines -match '^\s*Version\s*=') { $lines = $lines -replace '^\s*Version\s*=.*$', "Version=$new" }
        else                                  { $lines += "Version=$new" }
    } else { $lines = @('[General]', "Version=$new") }
    Set-Content -LiteralPath $ini -Value $lines -Encoding ASCII
}

function Add-GpoMachineExtension {
    # registers a client-side extension on the GPO so clients process the files we wrote
    param([guid]$Guid, [string]$CseGuid, [string]$ToolGuid)
    $b   = $Guid.ToString('B').ToUpper()
    $dn  = "CN=$b,CN=Policies,CN=System,$($script:Ctx.DomainDN)"
    $obj = Get-ADObject -Identity $dn -Server $script:Ctx.Pdc -Properties gPCMachineExtensionNames
    $pairs = @([regex]::Matches([string]$obj.gPCMachineExtensionNames, '\[[^\]]+\]') | ForEach-Object { $_.Value })
    if ($pairs | Where-Object { $_ -like "[[]$CseGuid*" }) { return }
    $pairs += "[$CseGuid$ToolGuid]"
    Set-ADObject -Identity $dn -Server $script:Ctx.Pdc -Replace @{ gPCMachineExtensionNames = (-join ($pairs | Sort-Object)) }
}

function Set-GpoSecurityOption {
    # Writes ONE "Registry Values" security option into the GPO's GptTmpl.inf (shows under Security Options in GPMC).
    # Keeps every other line of an existing file, reads back, registers the security CSE, bumps the version.
    param([guid]$Guid, [string]$Path, [int]$Value)
    $dir   = Join-Path (Get-GpoSysvolPath $Guid) 'Machine\Microsoft\Windows NT\SecEdit'
    $inf   = Join-Path $dir 'GptTmpl.inf'
    $entry = '{0}=4,{1}' -f $Path, $Value
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    if (Test-Path -LiteralPath $inf) { $lines = @(Get-Content -LiteralPath $inf) }
    else { $lines = @('[Unicode]', 'Unicode=yes', '[Version]', 'signature="$CHICAGO$"', 'Revision=1') }
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($l in $lines) {
        if (-not ([string]$l).Trim().StartsWith($Path + '=', [StringComparison]::OrdinalIgnoreCase)) { $out.Add([string]$l) }
    }
    $at = -1
    for ($i = 0; $i -lt $out.Count; $i++) { if ($out[$i].Trim() -ieq '[Registry Values]') { $at = $i; break } }
    if ($at -ge 0) { $out.Insert($at + 1, $entry) } else { $out.Add('[Registry Values]'); $out.Add($entry) }
    Set-Content -LiteralPath $inf -Value $out.ToArray() -Encoding Unicode
    if (-not (@(Get-Content -LiteralPath $inf) | Where-Object { $_.Trim() -ieq $entry })) { throw "GptTmpl.inf read-back failed for $Path" }
    Add-GpoMachineExtension -Guid $Guid -CseGuid '{827D319E-6EAC-11D2-A4EA-00C04F79F83A}' -ToolGuid '{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}'
    Step-GpoVersion -Guid $Guid
}

function Add-GpoLinkVerified {
    # Links the GPO (enabled) at a container, optionally at a fixed order, and reads it back
    param([string]$Target, [int]$Order = 0)
    $p = @{ Guid = $script:Ctx.GpoGuid; Target = $Target; LinkEnabled = 'Yes'; Domain = $script:Ctx.DnsRoot; Server = $script:Ctx.Pdc }
    if ($Order -gt 0) { $p['Order'] = $Order }
    $find = { (Get-GPInheritance -Target $Target -Domain $script:Ctx.DnsRoot -Server $script:Ctx.Pdc).GpoLinks | Where-Object { $_.GpoId -eq $script:Ctx.GpoGuid } }
    $l = & $find
    if (-not $l) { New-GPLink @p | Out-Null }
    elseif (-not $l.Enabled -or ($Order -gt 0 -and $l.Order -ne $Order)) { Set-GPLink @p | Out-Null }
    $l = & $find
    if (-not $l -or -not $l.Enabled) { throw "Link read-back failed at $Target" }
    "$Target (order $($l.Order))"
}

# =====================================================================================
# WHAT AD CAN TELL US (no event logs)
# =====================================================================================
function Get-ActiveComputers {
    # Enabled computer objects that logged on in the last 90 days and match an operatingSystem filter
    param([string]$OsFilter, [string]$Label)
    $ft = (Get-Date).AddDays(-90).ToFileTimeUtc()
    $c  = @(Get-ADObject -Server $script:Ctx.Pdc -ResultSetSize 100 -Properties operatingSystem `
            -LDAPFilter "(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(lastLogonTimestamp>=$ft)$OsFilter)")
    if ($c.Count -gt 0) { "$($c.Count) $Label, e.g. " + (($c | Select-Object -First 8 | ForEach-Object { '{0} ({1})' -f $_.Name, $_.operatingSystem }) -join ', ') }
}
function Get-LegacyWindowsFindings {
    Get-ActiveComputers -Label 'active Windows 2000/XP/2003 computer(s) (no AES Kerberos, NTLMv1 and SMB1 only)' `
        -OsFilter '(|(operatingSystem=Windows 2000*)(operatingSystem=Windows XP*)(operatingSystem=Windows Server 2003*)(operatingSystem=Windows NT*))'
}
function Get-NonWindowsFindings {
    Get-ActiveComputers -Label 'active non-Windows computer object(s) in AD' -OsFilter '(operatingSystem=*)(!(operatingSystem=Windows*))'
}

function Get-KerberosFindings {
    $f = New-Object System.Collections.Generic.List[string]
    # Each section is separate so one failing AD query shows up as a finding instead of hiding the others
    try {   # accounts that explicitly allow only RC4/DES (attribute set, no AES bit)
        $rc4 = @(Get-ADObject -Server $script:Ctx.Pdc -ResultSetSize 100 -Properties 'msDS-SupportedEncryptionTypes' -LDAPFilter '(&(objectClass=user)(msDS-SupportedEncryptionTypes=*)(!(msDS-SupportedEncryptionTypes=0))(!(msDS-SupportedEncryptionTypes:1.2.840.113556.1.4.804:=24)))')
        if ($rc4.Count -gt 0) { $f.Add("$($rc4.Count) account(s) limited to RC4/DES via msDS-SupportedEncryptionTypes, e.g. $((($rc4 | Select-Object -First 8 | ForEach-Object { $_.Name }) -join ', '))") }
    } catch { $f.Add("could not check RC4-only accounts: $($_.Exception.Message)") }
    try {   # 'Use only Kerberos DES encryption types'
        $des = @(Get-ADObject -Server $script:Ctx.Pdc -ResultSetSize 100 -LDAPFilter '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2097152))')
        if ($des.Count -gt 0) { $f.Add("$($des.Count) DES-only account(s), e.g. $((($des | Select-Object -First 8 | ForEach-Object { $_.Name }) -join ', '))") }
    } catch { $f.Add("could not check DES-only accounts: $($_.Exception.Message)") }
    try {   # trusts outside the forest use RC4 unless the trust advertises AES
        foreach ($t in @(Get-ADObject -Server $script:Ctx.Pdc -SearchBase "CN=System,$($script:Ctx.DomainDN)" -LDAPFilter '(objectClass=trustedDomain)' -Properties *)) {
            if (([int]$t.trustAttributes -band 0x20) -ne 0 -or [int]$t.trustType -eq 1) { continue }   # within forest / downlevel
            if (([int]$t.'msDS-SupportedEncryptionTypes' -band 24) -eq 0) { $f.Add("trust with $($t.trustPartner) does not advertise AES (tick 'The other domain supports Kerberos AES Encryption')") }
        }
    } catch { $f.Add("could not check trusts: $($_.Exception.Message)") }
    try { $leg = Get-LegacyWindowsFindings; if ($leg) { $f.Add($leg) } } catch { $f.Add("could not check legacy Windows computers: $($_.Exception.Message)") }
    try {   # passwords set before any AES-capable DC existed have no AES keys and cannot log on once RC4 is refused
        $created = @(Get-ADDomainController -Filter * -Server $script:Ctx.Pdc | Where-Object { $_.OperatingSystem -match 'Windows Server (2008|2012|2016|2019|2022|2025)' } |
            ForEach-Object { (Get-ADObject -Identity $_.ComputerObjectDN -Server $script:Ctx.Pdc -Properties whenCreated).whenCreated })
        if ($created.Count -gt 0) {
            $cut = $created | Sort-Object | Select-Object -First 1
            $k = Get-ADUser -Identity krbtgt -Server $script:Ctx.Pdc -Properties PasswordLastSet
            if ($k.PasswordLastSet -and $k.PasswordLastSet -lt $cut) { $f.Add("krbtgt password is from $($k.PasswordLastSet.ToString('yyyy-MM-dd')), before AES-capable DCs existed (no AES keys): reset it twice first") }
            $old = @(Get-ADObject -Server $script:Ctx.Pdc -ResultSetSize 100 -LDAPFilter "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(pwdLastSet>=1)(pwdLastSet<=$($cut.ToFileTimeUtc())))")
            if ($old.Count -gt 0) { $f.Add("$($old.Count) enabled user(s) with a password older than $($cut.ToString('yyyy-MM-dd')) (no AES keys, must change password), e.g. $((($old | Select-Object -First 8 | ForEach-Object { $_.Name }) -join ', '))") }
        } else { $f.Add('could not find an AES-capable DC, so the krbtgt / old-password check was skipped') }
    } catch { $f.Add("could not check krbtgt / old passwords: $($_.Exception.Message)") }
    $f.ToArray()
}

# =====================================================================================
# SETTINGS TABLE (single source of truth for apply AND verify)
#   Kind Sec = Security Option in GptTmpl.inf, Kind Reg = registry value via Set-GPRegistryValue
#   Value = the strong value, Fallback = value applied instead if you answer no, Find = what AD shows
# =====================================================================================
$Items = @(
    @{ Id='B06'; Title='Disable SMB1 (server)'; Kind='Reg'; Value=0; DcOnly=$false
       Key='HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; ValueName='SMB1'
       Breaks='SMB1-only devices (old NAS, scanners, XP/2003 machines)'
       Find={ Get-LegacyWindowsFindings } }
    @{ Id='B07'; Title='Kerberos: AES only (no RC4/DES)'; Kind='Sec'; Value=24; DcOnly=$false
       Path='MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\SupportedEncryptionTypes'
       Breaks='RC4-only accounts, trusts and services, plus old appliances, Linux keytabs and Java/SQL apps that cannot use AES'
       Hard={ if ([string]$script:Ctx.DomainMode -match '^Windows(2000|2003)') { "domain functional level is $($script:Ctx.DomainMode); AES Kerberos cannot work below 2008, raise it first" } }
       Find={ Get-KerberosFindings } }
    @{ Id='B08'; Title='LDAP server signing required (DC)'; Kind='Sec'; Value=2; DcOnly=$true
       Path='MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity'
       Breaks='apps, Linux (SSSD, nslcd), appliances and scripts that bind on port 389 with a cleartext password or without signing (use LDAPS or SASL signing)'
       Find={ Get-NonWindowsFindings } }
    @{ Id='B09'; Title='LDAP client signing required'; Kind='Sec'; Value=2; DcOnly=$false
       Path='MACHINE\System\CurrentControlSet\Services\LDAP\LDAPClientIntegrity'
       Breaks='Windows hosts that talk to non-Windows LDAP servers (OpenLDAP, appliances, proxies) on port 389 without signing'
       Find={ Get-NonWindowsFindings } }
    @{ Id='B10'; Title='LDAP channel binding always (DC)'; Kind='Reg'; Value=2; DcOnly=$true
       Key='HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'; ValueName='LdapEnforceChannelBinding'
       Breaks='LDAPS clients without channel binding support (unpatched or third-party software)'
       Find={ Get-NonWindowsFindings } }
    @{ Id='B11'; Title='NTLM: LmCompatibilityLevel 5 (NTLMv2 only; No = level 3)'; Kind='Sec'; Value=5; Fallback=3; DcOnly=$false
       Path='MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel'
       Breaks='NAS devices, scanners, old apps and Samba/Linux clients that still use LM/NTLMv1'
       Find={ @(Get-LegacyWindowsFindings) + @(Get-NonWindowsFindings) } }
    @{ Id='B12'; Title='SMB signing required (server)'; Kind='Sec'; Value=1; DcOnly=$false
       Path='MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature'
       Breaks='clients that cannot sign SMB (old NAS, Samba, MFP scanners, Linux CIFS mounts)'
       Find={ Get-NonWindowsFindings } }
    @{ Id='B13'; Title='SMB signing required (client)'; Kind='Sec'; Value=1; DcOnly=$false
       Path='MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature'
       Breaks='connections to unsigned NAS/Samba shares and old servers'
       Find={ Get-NonWindowsFindings } }
)

function Get-AppliedItems {
    # Items whose block succeeded in this run
    foreach ($it in $Items) {
        $row = $script:Results | Where-Object { $_.Block -eq $it.Id } | Select-Object -Last 1
        if ($row -and $row.Status -eq 'OK') { $it }
    }
}

# =====================================================================================
# B01-B05  Setup (first question: dry run or real run)
# =====================================================================================
$DryRun = Confirm-Yes -Question 'Dry run only? Shows what AD finds and asks nothing, changes nothing.' -DefaultYes $false

Invoke-Block -Id 'B01' -Name 'Environment checks (elevation, PowerShell version)' -Prereq {
    $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { return 'Not running elevated. Re-run as Administrator.' }
    if ($PSVersionTable.PSVersion.Major -lt 5) { return "PowerShell $($PSVersionTable.PSVersion) is too old (need 5.1+)." }
    $null
} -Action { 'Elevated, PowerShell ' + $PSVersionTable.PSVersion }

Invoke-Block -Id 'B02' -Name 'Load GroupPolicy and ActiveDirectory modules' -Prereq {
    $missing = @('GroupPolicy','ActiveDirectory') | Where-Object { -not (Get-Module -ListAvailable -Name $_) }
    if ($missing) { return "Missing module(s): $($missing -join ', '). Install with: Install-WindowsFeature GPMC,RSAT-AD-PowerShell (server) or the RSAT capabilities (client)." }
    Import-Module GroupPolicy, ActiveDirectory -ErrorAction Stop
    $script:Ctx.ModulesOk = $true
    $null
} -Action { 'Modules loaded' }

Invoke-Block -Id 'B03' -Name 'Domain context, SYSVOL access and permissions' -Prereq {
    if (-not $script:Ctx.ModulesOk) { return 'Modules not loaded (B02)' }
    try { $d = Get-ADDomain } catch { return "Cannot reach a domain: $($_.Exception.Message)" }
    $script:Ctx.DomainDN   = $d.DistinguishedName
    $script:Ctx.DnsRoot    = $d.DNSRoot
    $script:Ctx.Pdc        = $d.PDCEmulator
    $script:Ctx.DomainMode = [string]$d.DomainMode
    $script:Ctx.DcOuDN     = [string]$d.DomainControllersContainer
    try { $null = Get-ADDomainController -Server $script:Ctx.Pdc } catch { return "PDC emulator $($script:Ctx.Pdc) is not reachable." }
    $sysvol = "\\{0}\SYSVOL\{1}\Policies" -f $script:Ctx.Pdc, $script:Ctx.DnsRoot
    if (-not (Test-Path -LiteralPath $sysvol)) { return "Cannot read $sysvol" }
    $sids = [Security.Principal.WindowsIdentity]::GetCurrent().Groups | ForEach-Object { $_.Value }
    if (-not ($sids | Where-Object { $_ -match '-(512|519)$' })) {
        return 'Current user is not in Domain Admins / Enterprise Admins. Needed to create+link GPOs and edit SYSVOL.'
    }
    $script:Ctx.DomainOk = $true
    $null
} -Action { "Domain $($script:Ctx.DnsRoot) (functional level $($script:Ctx.DomainMode)), PDC $($script:Ctx.Pdc)" }

Invoke-Block -Id 'B04' -Name "Create GPO '$GpoName'" -Prereq {
    if (-not $script:Ctx.DomainOk) { return 'Domain context not ready (B03)' }
    $existing = Get-GPO -Name $GpoName -Domain $script:Ctx.DnsRoot -Server $script:Ctx.Pdc -ErrorAction SilentlyContinue
    if ($existing) { $script:Ctx.GpoGuid = $existing.Id; $script:Ctx.GpoExisted = $true }
    else           { $script:Ctx.GpoPlanned = $true }
    $null
} -Action {
    if ($script:Ctx.GpoExisted) { return "GPO already exists, reusing {$($script:Ctx.GpoGuid)}" }
    $g = New-GPO -Name $GpoName -Domain $script:Ctx.DnsRoot -Server $script:Ctx.Pdc -Comment 'Encryption and signing hardening'
    $script:Ctx.GpoGuid = $g.Id
    "Created {$($g.Id)}"
}

Invoke-Block -Id 'B05' -Name 'Link GPO at domain root (entire domain)' -Prereq {
    $r = Test-GpoReady; if ($r) { return $r }

    # Always link at the domain root so the GPO is in scope for the entire domain.
    $t = $script:Ctx.DomainDN
    try {
        $o = Get-ADObject -Identity $t -Server $script:Ctx.Pdc -Properties objectClass
    } catch {
        return "Could not verify domain root '$t': $($_.Exception.Message)"
    }
    if ([string]$o.ObjectClass -ne 'domainDNS') {
        return "Expected the domain root to be a domainDNS object, but found '$($o.ObjectClass)'"
    }

    $script:Ctx.LinkDN = $t
    $null
} -Action { 'Linked at domain root: ' + (Add-GpoLinkVerified -Target $script:Ctx.LinkDN) }

# =====================================================================================
# B06-B13  Settings: show what AD finds, then ask whether to turn each one on
# =====================================================================================
foreach ($it in $Items) {
    Invoke-Block -Id $it.Id -Name $it.Title -Prereq {
        $r = Test-GpoReady; if ($r) { return $r }
        if ($it.Hard) { $h = & $it.Hard; if ($h) { return "BLOCKED: $h" } }
        $found = @(& $it.Find)
        Write-Host "`n--- $($it.Title) ---" -ForegroundColor Yellow
        if ($found.Count -gt 0) { Write-Host 'AD shows:' -ForegroundColor Yellow; foreach ($x in $found) { Write-Host "  - $x" -ForegroundColor Yellow } }
        else { Write-Host 'AD shows nothing specific that would break.' -ForegroundColor DarkGray }
        Write-Host "Could break: $($it.Breaks)" -ForegroundColor Yellow
        if ($DryRun) { return $null }
        if (Confirm-Yes -Question "Turn on '$($it.Title)'?") { return $null }
        if ($it.Fallback) { Write-Host "Applying level $($it.Fallback) instead." -ForegroundColor Yellow; $it.Value = $it.Fallback; $it.FellBack = $true; return $null }
        'Left alone (you answered no)'
    } -Action {
        if ($it.Kind -eq 'Sec') {
            Set-GpoSecurityOption -Guid $script:Ctx.GpoGuid -Path $it.Path -Value $it.Value
            $what = $it.Path.Substring($it.Path.LastIndexOf('\') + 1)
        } else {
            Set-GpoReg -Key $it.Key -Name $it.ValueName -Type DWord -Value $it.Value
            $what = $it.ValueName
        }
        "$what = $($it.Value)" + $(if ($it.FellBack) { ' (strong level declined, fell back to this level)' } else { '' })
    }
}

# =====================================================================================
# B14  Settings that only exist on DCs would lose to any GPO linked nearer the DCs: link there too
# =====================================================================================
Invoke-Block -Id 'B14' -Name 'Link GPO at the top of the Domain Controllers OU' -Prereq {
    $r = Test-GpoReady; if ($r) { return $r }
    if (@(Get-AppliedItems | Where-Object { $_.DcOnly }).Count -eq 0) { return 'No DC-only setting was applied' }
    if ($script:Ctx.LinkDN -eq $script:Ctx.DcOuDN) { return 'Already linked there (B05)' }
    $null
} -Action { 'Linked at ' + (Add-GpoLinkVerified -Target $script:Ctx.DcOuDN -Order 1) }

# =====================================================================================
# B15-B18  Verification (read-only). B15-B17 check THIS machine, so run on a machine in scope of the GPO.
# =====================================================================================
Invoke-Block -Id 'B15' -Name 'gpupdate + confirm GPO is applied on this machine' -Prereq { Test-GpoReady } -Action {
    & gpupdate.exe /target:computer /force | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "gpupdate exited with code $LASTEXITCODE" }
    $gr = (& gpresult.exe /scope computer /r) -join "`n"
    $m  = [regex]::Match($gr, 'Applied Group Policy Objects\s*-+\s*(.*?)(\r?\n\s*\r?\n|\z)', 'Singleline')
    if (-not $m.Success) { return 'gpupdate ok, but gpresult output could not be parsed (non-English OS?). Relying on B16/B17.' }
    if ($m.Groups[1].Value -notmatch [regex]::Escape($GpoName)) {
        throw "'$GpoName' is NOT in this machine's applied GPO list. Check where it is linked, security filtering, blocked inheritance, WMI filters."
    }
    "'$GpoName' is in the applied GPO list"
}

Invoke-Block -Id 'B16' -Name 'Verify GPO contents (SYSVOL + registry.pol read-back)' -Prereq { Test-GpoReady } -Action {
    $inf = Join-Path (Get-GpoSysvolPath $script:Ctx.GpoGuid) 'Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf'
    $lines = @(); if (Test-Path -LiteralPath $inf) { $lines = @(Get-Content -LiteralPath $inf) }
    $bad = @(); $n = 0
    foreach ($it in @(Get-AppliedItems)) {
        $n++
        if ($it.Kind -eq 'Sec') {
            $want = '{0}=4,{1}' -f $it.Path, $it.Value
            if (-not ($lines | Where-Object { $_.Trim() -ieq $want })) { $bad += "GptTmpl.inf is missing '$want'" }
        } else {
            $got = Get-GPRegistryValue -Guid $script:Ctx.GpoGuid -Domain $script:Ctx.DnsRoot -Server $script:Ctx.Pdc -Key $it.Key -ValueName $it.ValueName -ErrorAction SilentlyContinue
            if (-not $got -or "$($got.Value)" -ne "$($it.Value)") { $bad += "$($it.Key)\$($it.ValueName) is '$($got.Value)', want '$($it.Value)'" }
        }
    }
    if ($bad.Count -gt 0) { throw "$($bad.Count) mismatch(es): $($bad -join '; ')" }
    "$n setting(s) present in the GPO"
}

Invoke-Block -Id 'B17' -Name 'Verify values in effect on THIS machine' -Prereq { Test-GpoReady } -Action {
    $isDc = ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4)
    $bad = @(); $n = 0
    foreach ($it in @(Get-AppliedItems)) {
        if ($it.DcOnly -and -not $isDc) { continue }
        if ($it.Kind -eq 'Sec') { $cut = $it.Path.LastIndexOf('\'); $key = $it.Path.Substring(0, $cut); $name = $it.Path.Substring($cut + 1) }
        else { $key = $it.Key; $name = $it.ValueName }
        $key = 'HKLM:\' + ($key -replace '^(MACHINE|HKLM)\\', '')
        $n++
        $item = Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue
        $prop = if ($item) { $item.PSObject.Properties[$name] } else { $null }
        if (-not $prop -or "$($prop.Value)" -ne "$($it.Value)") { $bad += "$name is '$($prop.Value)', want '$($it.Value)': this setting is being overwritten by another GPO" }
    }
    if ($bad.Count -gt 0) { throw ($bad -join '; ') }
    "$n value(s) in effect. A reboot is recommended for Kerberos / NTLM / SMB changes to apply everywhere."
}

Invoke-Block -Id 'B18' -Name 'Verify AD/SYSVOL version consistency and DC replication' -Prereq { Test-GpoReady } -Action {
    $b  = $script:Ctx.GpoGuid.ToString('B').ToUpper()
    $dn = "CN=$b,CN=Policies,CN=System,$($script:Ctx.DomainDN)"
    $want = [int](Get-ADObject -Identity $dn -Server $script:Ctx.Pdc -Properties versionNumber).versionNumber
    $lag = @(); $n = 0
    foreach ($dc in (Get-ADDomainController -Filter * -Server $script:Ctx.Pdc)) {
        $n++
        $ad = $null; $sv = $null
        try { $ad = [int](Get-ADObject -Identity $dn -Server $dc.HostName -Properties versionNumber).versionNumber } catch { }
        $ini = "\\{0}\SYSVOL\{1}\Policies\{2}\GPT.INI" -f $dc.HostName, $script:Ctx.DnsRoot, $b
        try {
            $line = Get-Content -LiteralPath $ini -ErrorAction Stop | Where-Object { $_ -match '^\s*Version\s*=' } | Select-Object -First 1
            $sv = [int](($line -split '=')[1])
        } catch { }
        if ($ad -ne $want -or $sv -ne $want) { $lag += "$($dc.HostName) (AD=$ad, SYSVOL=$sv, want $want)" }
    }
    if ($lag.Count -gt 0) { throw "Not yet consistent on: $($lag -join '; '). Replication may still be in progress, run the script again in a few minutes." }
    "Version $want present in AD and SYSVOL on all $n DC(s)"
}

# =====================================================================================
# SUMMARY
# =====================================================================================
Write-Host "`n================ SUMMARY ================" -ForegroundColor White
$script:Results | Format-Table Block, Status, Name, Detail -AutoSize -Wrap
$failed = @($script:Results | Where-Object Status -eq 'FAILED').Count
Write-Host ("OK: {0}  SKIPPED: {1}  FAILED: {2}" -f @($script:Results | Where-Object Status -eq 'OK').Count, @($script:Results | Where-Object Status -eq 'SKIPPED').Count, $failed)
if ($LogFile) { Write-Host "Full log: $LogFile" }
try { Stop-Transcript | Out-Null } catch { }
$global:LASTEXITCODE = [int]($failed -gt 0)   # exit-code style result without closing your session