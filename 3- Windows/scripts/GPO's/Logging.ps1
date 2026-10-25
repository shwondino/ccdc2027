<#
.SYNOPSIS
    Creates a GPO called "logging", links it to the domain root

.DESCRIPTION
    Run from an elevated Windows PowerShell 5.1 prompt on a DC (or a host with
    RSAT: GPMC + AD PowerShell) as a Domain Admin.

.PARAMETER GpoName         Name of the GPO to create / reuse. Default: logging
.PARAMETER TranscriptPath  PowerShell transcription output folder (on each client).
.PARAMETER BackupPath      Where backups of any existing GptTmpl.inf / audit.csv in the logging GPO are copied.
.PARAMETER DryRun          Run all prereq checks but change nothing.
.PARAMETER VerifyOnly      Make no changes; only run the read-only verification blocks (B16-B19) after the setup checks.
.PARAMETER Pause           Wait for Enter at the end (only useful if you launch it by right-click / double-click). Default: return to the prompt.
.PARAMETER SkipPS2Removal  Skip block B15 (local PowerShell 2.0 removal).
.PARAMETER SkipDCSyncSacl  Skip block B14 (SACL on the domain head for DCSync detection).

.EXAMPLE
    .\logging.ps1 -DryRun
#>
[CmdletBinding()]
param(
    [string]$GpoName        = 'logging',
    [string]$TranscriptPath = 'C:\PSTranscripts',
    [string]$BackupPath     = 'C:\GPO-Backups\logging',
    [switch]$DryRun,
    [switch]$VerifyOnly,
    [switch]$Pause,
    [switch]$SkipPS2Removal,
    [switch]$SkipDCSyncSacl
)

$ErrorActionPreference = 'Stop'
$script:Results = New-Object System.Collections.Generic.List[object]
$script:Ctx     = @{ ModulesOk = $false; DomainOk = $false; GpoGuid = $null; GpoPlanned = $false }

# Any unexpected error outside a block: show it and keep the window open
trap {
    Write-Host "`nUNHANDLED ERROR: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
    if ($Pause) { Read-Host 'Press Enter to close' | Out-Null }
    break
}

# Log goes next to the script (or %TEMP% if that is not possible), not the current directory
$LogDir = if ($PSScriptRoot) { $PSScriptRoot } else { $env:TEMP }
$LogFile = Join-Path $LogDir ("Logging-GPO-{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
try { Start-Transcript -Path $LogFile | Out-Null } catch { $LogFile = $null; Write-Warning "Could not start transcript: $($_.Exception.Message)" }

# =====================================================================================
# FRAMEWORK
# =====================================================================================
function Invoke-Block {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Name,
        [switch]$Verify,         # marks a read-only verification block
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
        if ($reason) {
            $status = 'SKIPPED'; $detail = [string]($reason | Select-Object -Last 1)
        }
        elseif ($DryRun) {
            $status = 'DRYRUN'; $detail = 'Prereqs passed, no changes made'
        }
        elseif ($VerifyOnly -and -not $Verify) {
            $status = 'SKIPPED'; $detail = 'VerifyOnly: change blocks are not run'
        }
        else {
            $out = & $Action
            if ($out) { $detail = [string]($out | Select-Object -Last 1) }
        }
    }
    catch {
        $status = 'FAILED'; $detail = $_.Exception.Message
    }
    $colour = @{ OK='Green'; SKIPPED='Yellow'; FAILED='Red'; DRYRUN='Gray' }[$status]
    Write-Host ("[{0}] {1}" -f $status, $detail) -ForegroundColor $colour
    $script:Results.Add([pscustomobject]@{ Block = $Id; Name = $Name; Status = $status; Detail = $detail })
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
    # read back to confirm
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
    $cur = [string]$obj.gPCMachineExtensionNames
    $pairs = @([regex]::Matches($cur, '\[[^\]]+\]') | ForEach-Object { $_.Value })
    if ($pairs | Where-Object { $_ -like "[[]$CseGuid*" }) { return }
    $pairs += "[$CseGuid$ToolGuid]"
    $new = -join ($pairs | Sort-Object)
    Set-ADObject -Identity $dn -Server $script:Ctx.Pdc -Replace @{ gPCMachineExtensionNames = $new }
}

function Remove-GpoMachineExtension {
    # removes a (wrong) client-side extension entry from the GPO
    param([guid]$Guid, [string]$CseGuid)
    $b   = $Guid.ToString('B').ToUpper()
    $dn  = "CN=$b,CN=Policies,CN=System,$($script:Ctx.DomainDN)"
    $obj = Get-ADObject -Identity $dn -Server $script:Ctx.Pdc -Properties gPCMachineExtensionNames
    $pairs = @([regex]::Matches([string]$obj.gPCMachineExtensionNames, '\[[^\]]+\]') | ForEach-Object { $_.Value })
    $keep  = @($pairs | Where-Object { $_ -notlike "[[]$CseGuid*" })
    if ($keep.Count -ne $pairs.Count) {
        Set-ADObject -Identity $dn -Server $script:Ctx.Pdc -Replace @{ gPCMachineExtensionNames = (-join $keep) }
    }
}

function Resolve-AuditCse {
    # Ask THIS machine which client-side extension is called "Audit ..." instead of trusting a hard-coded GUID
    $root = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions'
    foreach ($k in (Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
        $name = [string]$k.GetValue('')
        if ($name -match 'Audit') { return [pscustomobject]@{ Guid = $k.PSChildName; Name = $name } }
    }
    $null
}

$CSE_Security = '{827D319E-6EAC-11D2-A4EA-00C04F79F83A}'; $TOOL_Security = '{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}'
$CSE_Audit    = '{F3CCC681-B74C-4060-9F26-0101AD4B5E4C}'; $TOOL_Audit    = '{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}'

# Advanced Audit Policy table. Val: 0 none, 1 success, 2 failure, 3 both
$AuditTable = @(
    # ---- Account Logon (LG2-LG4) ----
    @{Sub='Credential Validation';                 Guid='{0CCE923F-69AE-11D9-BED3-505054503030}'; Val=3}
    @{Sub='Kerberos Authentication Service';       Guid='{0CCE9242-69AE-11D9-BED3-505054503030}'; Val=3}
    @{Sub='Kerberos Service Ticket Operations';    Guid='{0CCE9240-69AE-11D9-BED3-505054503030}'; Val=3}
    @{Sub='Other Account Logon Events';            Guid='{0CCE9241-69AE-11D9-BED3-505054503030}'; Val=3}
    # ---- Account Management (LG6-LG8) ----
    @{Sub='User Account Management';               Guid='{0CCE9235-69AE-11D9-BED3-505054503030}'; Val=3}
    @{Sub='Computer Account Management';           Guid='{0CCE9236-69AE-11D9-BED3-505054503030}'; Val=3}
    @{Sub='Security Group Management';             Guid='{0CCE9237-69AE-11D9-BED3-505054503030}'; Val=3}
    @{Sub='Distribution Group Management';         Guid='{0CCE9238-69AE-11D9-BED3-505054503030}'; Val=1}
    @{Sub='Application Group Management';          Guid='{0CCE9239-69AE-11D9-BED3-505054503030}'; Val=3}
    @{Sub='Other Account Management Events';       Guid='{0CCE923A-69AE-11D9-BED3-505054503030}'; Val=3}
    # ---- Detailed Tracking (LG13) ----
    @{Sub='Process Creation';                      Guid='{0CCE922B-69AE-11D9-BED3-505054503030}'; Val=1}
    @{Sub='Process Termination';                   Guid='{0CCE922C-69AE-11D9-BED3-505054503030}'; Val=0}
    @{Sub='DPAPI Activity';                        Guid='{0CCE922D-69AE-11D9-BED3-505054503030}'; Val=0}
    @{Sub='RPC Events';                            Guid='{0CCE922E-69AE-11D9-BED3-505054503030}'; Val=0}
    @{Sub='Plug and Play Events';                  Guid='{0CCE9248-69AE-11D9-BED3-505054503030}'; Val=1}
    @{Sub='Token Right Adjusted Events';           Guid='{0CCE924A-69AE-11D9-BED3-505054503030}'; Val=0}
    # ---- DS Access (LG9, LG10) ----
    @{Sub='Directory Service Access';              Guid='{0CCE923B-69AE-11D9-BED3-505054503030}'; Val=3}
    @{Sub='Directory Service Changes';             Guid='{0CCE923C-69AE-11D9-BED3-505054503030}'; Val=1}
    @{Sub='Directory Service Replication';         Guid='{0CCE923D-69AE-11D9-BED3-505054503030}'; Val=0}
    @{Sub='Detailed Directory Service Replication';Guid='{0CCE923E-69AE-11D9-BED3-505054503030}'; Val=0}
    # ---- Logon/Logoff (LG5) ----
    @{Sub='Logon';                                 Guid='{0CCE9215-69AE-11D9-BED3-505054503030}'; Val=3}
    @{Sub='Logoff';                                Guid='{0CCE9216-69AE-11D9-BED3-505054503030}'; Val=1}
    @{Sub='Account Lockout';                       Guid='{0CCE9217-69AE-11D9-BED3-505054503030}'; Val=2}
    @{Sub='IPsec Main Mode';                       Guid='{0CCE9218-69AE-11D9-BED3-505054503030}'; Val=0}
    @{Sub='IPsec Quick Mode';                      Guid='{0CCE9219-69AE-11D9-BED3-505054503030}'; Val=0}
    @{Sub='IPsec Extended Mode';                   Guid='{0CCE921A-69AE-11D9-BED3-505054503030}'; Val=0}
    @{Sub='Special Logon';                         Guid='{0CCE921B-69AE-11D9-BED3-505054503030}'; Val=1}
    @{Sub='Other Logon/Logoff Events';             Guid='{0CCE921C-69AE-11D9-BED3-505054503030}'; Val=3}
    @{Sub='Group Membership';                      Guid='{0CCE9249-69AE-11D9-BED3-505054503030}'; Val=1}
    # ---- Object Access (LG17, LG18; noisy ones explicitly OFF) ----
    @{Sub='File Share';                            Guid='{0CCE9224-69AE-11D9-BED3-505054503030}'; Val=3}
    @{Sub='Removable Storage';                     Guid='{0CCE9245-69AE-11D9-BED3-505054503030}'; Val=3}
    @{Sub='Certification Services';                Guid='{0CCE9221-69AE-11D9-BED3-505054503030}'; Val=3}
    @{Sub='Filtering Platform Connection';         Guid='{0CCE9226-69AE-11D9-BED3-505054503030}'; Val=0}
    @{Sub='Filtering Platform Packet Drop';        Guid='{0CCE9225-69AE-11D9-BED3-505054503030}'; Val=0}
    @{Sub='Detailed File Share';                   Guid='{0CCE9244-69AE-11D9-BED3-505054503030}'; Val=0}
    @{Sub='File System';                           Guid='{0CCE921D-69AE-11D9-BED3-505054503030}'; Val=0}
    @{Sub='Registry';                              Guid='{0CCE921E-69AE-11D9-BED3-505054503030}'; Val=0}
    @{Sub='Kernel Object';                         Guid='{0CCE921F-69AE-11D9-BED3-505054503030}'; Val=0}
    @{Sub='SAM';                                   Guid='{0CCE9220-69AE-11D9-BED3-505054503030}'; Val=0}
    @{Sub='Application Generated';                 Guid='{0CCE9222-69AE-11D9-BED3-505054503030}'; Val=0}
    @{Sub='Handle Manipulation';                   Guid='{0CCE9223-69AE-11D9-BED3-505054503030}'; Val=0}
    @{Sub='Other Object Access Events';            Guid='{0CCE9227-69AE-11D9-BED3-505054503030}'; Val=0}
    @{Sub='Central Policy Staging';                Guid='{0CCE9246-69AE-11D9-BED3-505054503030}'; Val=0}
    # ---- Policy Change (LG11, LG12) ----
    @{Sub='Audit Policy Change';                   Guid='{0CCE922F-69AE-11D9-BED3-505054503030}'; Val=3}
    @{Sub='Authentication Policy Change';          Guid='{0CCE9230-69AE-11D9-BED3-505054503030}'; Val=1}
    @{Sub='Authorization Policy Change';           Guid='{0CCE9231-69AE-11D9-BED3-505054503030}'; Val=1}
    @{Sub='MPSSVC Rule-Level Policy Change';       Guid='{0CCE9232-69AE-11D9-BED3-505054503030}'; Val=0}
    @{Sub='Filtering Platform Policy Change';      Guid='{0CCE9233-69AE-11D9-BED3-505054503030}'; Val=0}
    @{Sub='Other Policy Change Events';            Guid='{0CCE9234-69AE-11D9-BED3-505054503030}'; Val=0}
    # ---- Privilege Use (LG15) ----
    @{Sub='Sensitive Privilege Use';               Guid='{0CCE9228-69AE-11D9-BED3-505054503030}'; Val=3}
    @{Sub='Non Sensitive Privilege Use';           Guid='{0CCE9229-69AE-11D9-BED3-505054503030}'; Val=0}
    @{Sub='Other Privilege Use Events';            Guid='{0CCE922A-69AE-11D9-BED3-505054503030}'; Val=0}
    # ---- System (LG16) ----
    @{Sub='Security State Change';                 Guid='{0CCE9210-69AE-11D9-BED3-505054503030}'; Val=1}
    @{Sub='Security System Extension';             Guid='{0CCE9211-69AE-11D9-BED3-505054503030}'; Val=1}
    @{Sub='System Integrity';                      Guid='{0CCE9212-69AE-11D9-BED3-505054503030}'; Val=3}
    @{Sub='IPsec Driver';                          Guid='{0CCE9213-69AE-11D9-BED3-505054503030}'; Val=3}
    @{Sub='Other System Events';                   Guid='{0CCE9214-69AE-11D9-BED3-505054503030}'; Val=3}
)
$InclusionText = @{ 0='No Auditing'; 1='Success'; 2='Failure'; 3='Success and Failure' }

# =====================================================================================
# B01  Environment (elevation, PowerShell version)
# =====================================================================================
Invoke-Block -Id 'B01' -Name 'Environment checks (elevation, PowerShell version)' -Prereq {
    $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { return 'Not running elevated. Re-run as Administrator.' }
    if ($PSVersionTable.PSVersion.Major -lt 5) { return "PowerShell $($PSVersionTable.PSVersion) is too old (need 5.1+)." }
    $null
} -Action { 'Elevated, PowerShell ' + $PSVersionTable.PSVersion }

# =====================================================================================
# B02  Required modules
# =====================================================================================
Invoke-Block -Id 'B02' -Name 'Load GroupPolicy and ActiveDirectory modules' -Prereq {
    $missing = @('GroupPolicy','ActiveDirectory') | Where-Object { -not (Get-Module -ListAvailable -Name $_) }
    if ($missing) { return "Missing module(s): $($missing -join ', '). Install with: Install-WindowsFeature GPMC,RSAT-AD-PowerShell (server) or the RSAT capabilities (client)." }
    Import-Module GroupPolicy, ActiveDirectory -ErrorAction Stop
    $script:Ctx.ModulesOk = $true
    $null
} -Action { 'Modules loaded' }

# =====================================================================================
# B03  Domain context, PDC reachability, SYSVOL access, permissions
# =====================================================================================
Invoke-Block -Id 'B03' -Name 'Domain context, SYSVOL access and permissions' -Prereq {
    if (-not $script:Ctx.ModulesOk) { return 'Modules not loaded (B02)' }
    try { $d = Get-ADDomain } catch { return "Cannot reach a domain: $($_.Exception.Message)" }
    $script:Ctx.DomainDN = $d.DistinguishedName
    $script:Ctx.DnsRoot  = $d.DNSRoot
    $script:Ctx.Pdc      = $d.PDCEmulator
    $script:Ctx.DomainSid = $d.DomainSID.Value
    try { $null = Get-ADDomainController -Server $script:Ctx.Pdc } catch { return "PDC emulator $($script:Ctx.Pdc) is not reachable." }
    $sysvol = "\\{0}\SYSVOL\{1}\Policies" -f $script:Ctx.Pdc, $script:Ctx.DnsRoot
    if (-not (Test-Path -LiteralPath $sysvol)) { return "Cannot read $sysvol" }
    $sids = [Security.Principal.WindowsIdentity]::GetCurrent().Groups | ForEach-Object { $_.Value }
    if (-not ($sids | Where-Object { $_ -match '-(512|519)$' })) {
        return 'Current user is not in Domain Admins / Enterprise Admins. Needed to create+link GPOs, edit SYSVOL and set the domain SACL.'
    }
    $script:Ctx.DomainOk = $true
    $null
} -Action { "Domain $($script:Ctx.DnsRoot), PDC $($script:Ctx.Pdc)" }

# =====================================================================================
# B04  Create (or reuse) the GPO
# =====================================================================================
Invoke-Block -Id 'B04' -Name "Create GPO '$GpoName'" -Prereq {
    if (-not $script:Ctx.DomainOk) { return 'Domain context not ready (B03)' }
    $existing = Get-GPO -Name $GpoName -Domain $script:Ctx.DnsRoot -Server $script:Ctx.Pdc -ErrorAction SilentlyContinue
    if ($existing) { $script:Ctx.GpoGuid = $existing.Id; $script:Ctx.GpoExisted = $true }
    else           { $script:Ctx.GpoPlanned = $true }
    $null
} -Action {
    if ($script:Ctx.GpoExisted) { return "GPO already exists, reusing {$($script:Ctx.GpoGuid)}" }
    $g = New-GPO -Name $GpoName -Domain $script:Ctx.DnsRoot -Server $script:Ctx.Pdc -Comment 'Advanced audit + PowerShell logging (low/low-med risk)'
    $script:Ctx.GpoGuid = $g.Id
    "Created {$($g.Id)}"
}

# =====================================================================================
# B05  Link GPO to the domain root (with read-back)
# =====================================================================================
Invoke-Block -Id 'B05' -Name 'Link GPO to domain root' -Prereq { Test-GpoReady } -Action {
    $inh  = Get-GPInheritance -Target $script:Ctx.DomainDN -Domain $script:Ctx.DnsRoot -Server $script:Ctx.Pdc
    $link = $inh.GpoLinks | Where-Object { $_.GpoId -eq $script:Ctx.GpoGuid }
    if (-not $link) {
        New-GPLink -Guid $script:Ctx.GpoGuid -Target $script:Ctx.DomainDN -LinkEnabled Yes -Order 1 `
            -Domain $script:Ctx.DnsRoot -Server $script:Ctx.Pdc | Out-Null
        $msg = 'Linked at domain root, link order 1'
    }
    elseif (-not $link.Enabled) {
        Set-GPLink -Guid $script:Ctx.GpoGuid -Target $script:Ctx.DomainDN -LinkEnabled Yes `
            -Domain $script:Ctx.DnsRoot -Server $script:Ctx.Pdc | Out-Null
        $msg = 'Link existed but was disabled, now enabled'
    }
    else { $msg = 'Already linked and enabled' }
    # verify
    $inh2  = Get-GPInheritance -Target $script:Ctx.DomainDN -Domain $script:Ctx.DnsRoot -Server $script:Ctx.Pdc
    $link2 = $inh2.GpoLinks | Where-Object { $_.GpoId -eq $script:Ctx.GpoGuid }
    if (-not $link2 -or -not $link2.Enabled) { throw 'Link read-back failed: GPO is not linked+enabled at the domain root' }
    "$msg (verified, order $($link2.Order), enforced=$($link2.Enforced))"
}

# =====================================================================================
# B06  SCENoApplyLegacyAuditPolicy = 1 (subcategories override categories)  [SI14/LG1]
# =====================================================================================
Invoke-Block -Id 'B06' -Name 'Force audit subcategory settings (SCENoApplyLegacyAuditPolicy=1)' -Prereq {
    $r = Test-GpoReady; if ($r) { return $r }
    $script:Ctx.GpoPath = Get-GpoSysvolPath $script:Ctx.GpoGuid
    if (-not (Test-Path -LiteralPath $script:Ctx.GpoPath)) { return "GPO folder not found in SYSVOL: $($script:Ctx.GpoPath)" }
    $null
} -Action {
    $dir = Join-Path $script:Ctx.GpoPath 'Machine\Microsoft\Windows NT\SecEdit'
    $inf = Join-Path $dir 'GptTmpl.inf'
    $setting = 'MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy=4,1'
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    if (Test-Path -LiteralPath $inf) {
        New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null
        Copy-Item -LiteralPath $inf -Destination (Join-Path $BackupPath 'GptTmpl.inf.bak') -Force
        $lines = @(Get-Content -LiteralPath $inf) | Where-Object { $_ -notmatch 'SCENoApplyLegacyAuditPolicy' }
        $idx = -1
        for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i].Trim() -eq '[Registry Values]') { $idx = $i; break } }
        if ($idx -ge 0) { $lines = @($lines[0..$idx]) + $setting + @($lines[($idx+1)..($lines.Count)] | Where-Object { $_ -ne $null }) }
        else            { $lines = @($lines) + '[Registry Values]' + $setting }
        Set-Content -LiteralPath $inf -Value $lines -Encoding Unicode
    } else {
        $content = @('[Unicode]','Unicode=yes','[Version]','signature="$CHICAGO$"','Revision=1','[Registry Values]',$setting)
        Set-Content -LiteralPath $inf -Value $content -Encoding Unicode
    }
    Add-GpoMachineExtension -Guid $script:Ctx.GpoGuid -CseGuid $CSE_Security -ToolGuid $TOOL_Security
    Step-GpoVersion -Guid $script:Ctx.GpoGuid
    'GptTmpl.inf written, security CSE registered, version bumped'
}

# =====================================================================================
# B07  Advanced Audit Policy subcategories (audit.csv)  [LG1-LG18, EX25-EX34]
# =====================================================================================
Invoke-Block -Id 'B07' -Name 'Advanced Audit Policy subcategories (audit.csv)' -Prereq {
    $r = Test-GpoReady; if ($r) { return $r }
    $script:Ctx.GpoPath = Get-GpoSysvolPath $script:Ctx.GpoGuid
    if (-not (Test-Path -LiteralPath $script:Ctx.GpoPath)) { return "GPO folder not found in SYSVOL: $($script:Ctx.GpoPath)" }
    $bad = $AuditTable | Where-Object { $_.Guid -notmatch '^\{[0-9A-F]{8}(-[0-9A-F]{4}){3}-[0-9A-F]{12}\}$' -or $_.Val -notin 0..3 }
    if ($bad) { return "Audit table has invalid rows: $(($bad.Sub) -join ', ')" }
    $null
} -Action {
    $dir = Join-Path $script:Ctx.GpoPath 'Machine\Microsoft\Windows NT\Audit'
    $csv = Join-Path $dir 'audit.csv'
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    if (Test-Path -LiteralPath $csv) {
        New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null
        Copy-Item -LiteralPath $csv -Destination (Join-Path $BackupPath 'audit.csv.bak') -Force
    }
    $rows = @('Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value')
    foreach ($a in $AuditTable) { $rows += ",System,{0},{1},{2},,{3}" -f $a.Sub, $a.Guid, $InclusionText[[int]$a.Val], $a.Val }
    [IO.File]::WriteAllText($csv, (($rows -join "`r`n") + "`r`n"), [Text.Encoding]::ASCII)
    $check = @(Get-Content -LiteralPath $csv).Count
    if ($check -ne $rows.Count) { throw "audit.csv read-back has $check lines, expected $($rows.Count)" }
    $found = Resolve-AuditCse
    if ($found) {
        $auditCse = $found.Guid
        Write-Host "   Audit CSE on this machine: $auditCse ($($found.Name))"
        if ($auditCse -ne $CSE_Audit) { Remove-GpoMachineExtension -Guid $script:Ctx.GpoGuid -CseGuid $CSE_Audit }
    } else {
        $auditCse = $CSE_Audit
        Write-Warning "Could not find an 'Audit' client-side extension in the registry; using built-in default $CSE_Audit"
    }
    Add-GpoMachineExtension -Guid $script:Ctx.GpoGuid -CseGuid $auditCse -ToolGuid $TOOL_Audit
    Step-GpoVersion -Guid $script:Ctx.GpoGuid
    "audit.csv written with $($AuditTable.Count) subcategories, audit CSE registered, version bumped"
}

# =====================================================================================
# B08  Command line in process creation events (4688)  [LG14, EX29]
# =====================================================================================
Invoke-Block -Id 'B08' -Name 'Include command line in 4688 events' -Prereq { Test-GpoReady } -Action {
    Set-GpoReg -Key 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled' -Type DWord -Value 1
    'ProcessCreationIncludeCmdLine_Enabled = 1'
}

# =====================================================================================
# B09  PowerShell script block logging (4104)  [EX35]
# =====================================================================================
Invoke-Block -Id 'B09' -Name 'PowerShell Script Block Logging' -Prereq { Test-GpoReady } -Action {
    Set-GpoReg -Key 'HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Type DWord -Value 1
    'EnableScriptBlockLogging = 1'
}

# =====================================================================================
# B10  PowerShell module logging (4103), all modules  [EX36, EX37]
# =====================================================================================
Invoke-Block -Id 'B10' -Name 'PowerShell Module Logging (all modules)' -Prereq { Test-GpoReady } -Action {
    Set-GpoReg -Key 'HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Name 'EnableModuleLogging' -Type DWord -Value 1
    Set-GpoReg -Key 'HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' -Name '*' -Type String -Value '*'
    'EnableModuleLogging = 1, ModuleNames * = *'
}

# =====================================================================================
# B11  PowerShell transcription  [LG19]
# =====================================================================================
Invoke-Block -Id 'B11' -Name "PowerShell Transcription -> $TranscriptPath" -Prereq {
    $r = Test-GpoReady; if ($r) { return $r }
    if ($TranscriptPath -notmatch '^([A-Za-z]:\\|\\\\)') { return "TranscriptPath '$TranscriptPath' is not an absolute local path or UNC path." }
    $null
} -Action {
    $k = 'HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription'
    Set-GpoReg -Key $k -Name 'EnableTranscripting'    -Type DWord  -Value 1
    Set-GpoReg -Key $k -Name 'EnableInvocationHeader' -Type DWord  -Value 1
    Set-GpoReg -Key $k -Name 'OutputDirectory'        -Type String -Value $TranscriptPath
    "Transcription on, output $TranscriptPath (transcripts can contain secrets: lock down that folder's ACL)"
}

# =====================================================================================
# B12  Security log size 1 GB  [EX38]
# =====================================================================================
Invoke-Block -Id 'B12' -Name 'Security event log max size (1 GB)' -Prereq { Test-GpoReady } -Action {
    Set-GpoReg -Key 'HKLM\Software\Policies\Microsoft\Windows\EventLog\Security' -Name 'MaxSize' -Type DWord -Value 1048576
    # The Event Log service may not re-read the policy until the next boot, so also apply it now on this machine
    $info = Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue
    $local = ''
    if ($info -and $info.MaximumSizeInBytes -lt 1073741824) {
        & wevtutil.exe sl Security /ms:1073741824
        if ($LASTEXITCODE -ne 0) { throw "wevtutil failed for Security (exit $LASTEXITCODE)" }
        $local = ', applied now on this machine'
    }
    "Security MaxSize = 1048576 KB in GPO (other machines apply it at the latest by next boot)$local"
}

# =====================================================================================
# B13  PowerShell / Sysmon / Defender log sizes  [LG22]
#   The Event Log policy keys only work for Application/Security/System/Setup, so these
#   three are set by a computer STARTUP SCRIPT in the GPO (applies at next boot) and are
#   also applied right now on this machine.
# =====================================================================================
Invoke-Block -Id 'B13' -Name 'PowerShell/Sysmon/Defender log sizes (startup script + local apply)' -Prereq {
    $r = Test-GpoReady; if ($r) { return $r }
    $script:Ctx.GpoPath = Get-GpoSysvolPath $script:Ctx.GpoGuid
    if (-not (Test-Path -LiteralPath $script:Ctx.GpoPath)) { return "GPO folder not found in SYSVOL: $($script:Ctx.GpoPath)" }
    $ini = Join-Path $script:Ctx.GpoPath 'Machine\Scripts\psscripts.ini'
    if ((Test-Path -LiteralPath $ini) -and -not (Select-String -LiteralPath $ini -Pattern 'Set-LogSizes.ps1' -Quiet)) {
        return 'psscripts.ini in the logging GPO already has other entries; not overwriting.'
    }
    $null
} -Action {
    $bytes = 268435456   # 256 MB
    $dir = Join-Path $script:Ctx.GpoPath 'Machine\Scripts\Startup'
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $startup = @'
$want = 268435456
foreach ($l in 'Microsoft-Windows-PowerShell/Operational','Microsoft-Windows-Sysmon/Operational','Microsoft-Windows-Windows Defender/Operational') {
    try {
        $i = Get-WinEvent -ListLog $l -ErrorAction Stop
        if ($i.MaximumSizeInBytes -lt $want) { & wevtutil.exe sl $l /ms:$want }
    } catch { }
}
'@
    Set-Content -LiteralPath (Join-Path $dir 'Set-LogSizes.ps1') -Value $startup -Encoding ASCII
    Set-Content -LiteralPath (Join-Path $script:Ctx.GpoPath 'Machine\Scripts\psscripts.ini') `
        -Value @('[Startup]', '0CmdLine=Set-LogSizes.ps1', '0Parameters=') -Encoding Unicode
    Add-GpoMachineExtension -Guid $script:Ctx.GpoGuid -CseGuid '{42B5FAAE-6536-11D2-AE5A-0000F87571E3}' -ToolGuid '{40B6664F-4972-11D1-A7CA-0000F87571E3}'
    Step-GpoVersion -Guid $script:Ctx.GpoGuid
    # apply immediately on this machine too
    $applied = @()
    foreach ($l in 'Microsoft-Windows-PowerShell/Operational','Microsoft-Windows-Sysmon/Operational','Microsoft-Windows-Windows Defender/Operational') {
        $info = Get-WinEvent -ListLog $l -ErrorAction SilentlyContinue
        if ($info -and $info.MaximumSizeInBytes -lt $bytes) {
            & wevtutil.exe sl $l /ms:$bytes
            if ($LASTEXITCODE -ne 0) { throw "wevtutil failed for $l (exit $LASTEXITCODE)" }
            $applied += $l
        }
    }
    "Startup script + psscripts.ini written (other machines pick it up at next boot); applied now locally to $($applied.Count) log(s)"
}

# =====================================================================================
# B14  SACL on the domain head for DCSync detection (4662)  [LG10]
# =====================================================================================
Invoke-Block -Id 'B14' -Name 'DCSync detection SACL on domain root' -Prereq {
    if ($SkipDCSyncSacl) { return 'Skipped by -SkipDCSyncSacl' }
    if (-not $script:Ctx.DomainOk) { return 'Domain context not ready (B03)' }
    if (-not (Test-Path -LiteralPath "AD:\$($script:Ctx.DomainDN)")) { return 'AD: drive / domain head not accessible' }
    $null
} -Action {
    $path     = "AD:\$($script:Ctx.DomainDN)"
    $acl      = Get-Acl -Path $path -Audit
    $everyone = New-Object Security.Principal.SecurityIdentifier ([Security.Principal.WellKnownSidType]::WorldSid, $null)
    $guids    = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',   # DS-Replication-Get-Changes
                '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2',   # DS-Replication-Get-Changes-All
                '89e95b76-444d-4c62-991a-0facbeda640c'    # DS-Replication-Get-Changes-In-Filtered-Set
    $added = 0
    foreach ($g in $guids) {
        $exists = $acl.GetAuditRules($true, $false, [Security.Principal.SecurityIdentifier]) |
                  Where-Object { $_.ObjectType -eq [guid]$g -and $_.IdentityReference.Value -eq $everyone.Value }
        if (-not $exists) {
            $rule = New-Object DirectoryServices.ActiveDirectoryAuditRule($everyone, 'ExtendedRight', 'Success', [guid]$g, 'None')
            $acl.AddAuditRule($rule)
            $added++
        }
    }
    if ($added -gt 0) { Set-Acl -Path $path -AclObject $acl }
    # verify
    $acl2 = Get-Acl -Path $path -Audit
    foreach ($g in $guids) {
        $ok = $acl2.GetAuditRules($true, $false, [Security.Principal.SecurityIdentifier]) |
              Where-Object { $_.ObjectType -eq [guid]$g -and $_.IdentityReference.Value -eq $everyone.Value }
        if (-not $ok) { throw "SACL read-back: rule for $g is missing on the domain root" }
    }
    "$added audit rule(s) added ($($guids.Count - $added) already present), all $($guids.Count) verified"
}

# =====================================================================================
# B15  Remove PowerShell 2.0 on THIS machine only  [LG25]
#      (cannot be set through a GPO; other machines need a separate rollout)
# =====================================================================================
Invoke-Block -Id 'B15' -Name 'Remove PowerShell 2.0 (local machine only)' -Prereq {
    if ($SkipPS2Removal) { return 'Skipped by -SkipPS2Removal' }
    if (-not (Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue)) { return 'DISM cmdlets (Get-WindowsOptionalFeature) not available' }
    $f = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction SilentlyContinue
    if (-not $f) { return 'PowerShell 2.0 feature not present on this OS' }
    if ($f.State -ne 'Enabled') { return "PowerShell 2.0 already $($f.State)" }
    $null
} -Action {
    $r = Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart
    $st = (Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root).State
    if ($st -eq 'Enabled') { throw 'Read-back: PowerShell 2.0 feature still reports Enabled' }
    if ($r.RestartNeeded) { 'Disabled, reboot needed to finish (local machine only)' } else { 'Disabled (local machine only)' }
}

# =====================================================================================
# VERIFICATION BLOCKS (read-only; these prove the settings are actually in effect)
#   NOTE: B16-B18 check THIS machine, so run the script on a machine that is in scope of
#   the GPO (a DC at the domain root is). B19 checks the GPO has reached every DC.
# =====================================================================================

# B16  Force a policy refresh and confirm the GPO shows as applied on this machine
Invoke-Block -Id 'B16' -Name 'gpupdate + confirm GPO is applied on this machine' -Verify -Prereq { Test-GpoReady } -Action {
    & gpupdate.exe /target:computer /force | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "gpupdate exited with code $LASTEXITCODE" }
    $gr = (& gpresult.exe /scope computer /r) -join "`n"
    $m  = [regex]::Match($gr, 'Applied Group Policy Objects\s*-+\s*(.*?)(\r?\n\s*\r?\n|\z)', 'Singleline')
    if (-not $m.Success) { return 'gpupdate ok, but gpresult output could not be parsed (non-English OS?). Relying on B17/B18 value checks.' }
    if ($m.Groups[1].Value -notmatch [regex]::Escape($GpoName)) {
        throw "'$GpoName' is NOT in this machine's applied GPO list. Check scope, security filtering, blocked inheritance, WMI filters."
    }
    "'$GpoName' is in the applied GPO list"
}

# B17  Effective advanced audit policy matches what the script defined
Invoke-Block -Id 'B17' -Name 'Verify effective audit policy (auditpol)' -Verify -Prereq {
    if (-not (Get-Command auditpol.exe -ErrorAction SilentlyContinue)) { return 'auditpol.exe not found' }
    Test-GpoReady
} -Action {
    $bad = @()
    foreach ($a in $AuditTable) {
        $line   = (& auditpol.exe /get /subcategory:"$($a.Guid)" /r) | ConvertFrom-Csv
        $actual = $line.'Inclusion Setting'
        if ($actual -ne $InclusionText[[int]$a.Val]) { $bad += "$($a.Sub) (is '$actual', want '$($InclusionText[[int]$a.Val])')" }
    }
    $lsa = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name SCENoApplyLegacyAuditPolicy -ErrorAction SilentlyContinue).SCENoApplyLegacyAuditPolicy
    if ($lsa -ne 1) { $bad += "SCENoApplyLegacyAuditPolicy is '$lsa', want 1" }
    if ($bad.Count -gt 0) {
        $bad | ForEach-Object { Write-Host "   - $_" -ForegroundColor Red }
        try {
            $dn = "CN=$($script:Ctx.GpoGuid.ToString('B').ToUpper()),CN=Policies,CN=System,$($script:Ctx.DomainDN)"
            Write-Host "   gPCMachineExtensionNames = $((Get-ADObject -Identity $dn -Server $script:Ctx.Pdc -Properties gPCMachineExtensionNames).gPCMachineExtensionNames)"
            Write-Host "   audit.csv present in SYSVOL = $(Test-Path -LiteralPath (Join-Path (Get-GpoSysvolPath $script:Ctx.GpoGuid) 'Machine\Microsoft\Windows NT\Audit\audit.csv'))"
            $f = Resolve-AuditCse
            Write-Host "   Audit CSE registered on this machine = $(if ($f) { $f.Guid + ' (' + $f.Name + ')' } else { 'NOT FOUND' })"
        } catch { }
        throw "$($bad.Count) mismatch(es), full list and diagnostics printed above"
    }
    "All $($AuditTable.Count) subcategories and SCENoApplyLegacyAuditPolicy are in effect"
}

# B18  Registry-based policy values are in effect, and event log sizes took effect
Invoke-Block -Id 'B18' -Name 'Verify registry policies + event log sizes in effect' -Verify -Prereq { Test-GpoReady } -Action {
    $expect = @(
        @{P='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit';       N='ProcessCreationIncludeCmdLine_Enabled'; V=1}
        @{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging';       N='EnableScriptBlockLogging'; V=1}
        @{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging';            N='EnableModuleLogging'; V=1}
        @{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames'; N='*'; V='*'}
        @{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription';            N='EnableTranscripting'; V=1}
        @{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription';            N='EnableInvocationHeader'; V=1}
        @{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription';            N='OutputDirectory'; V=$TranscriptPath}
        @{P='HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security';                   N='MaxSize'; V=1048576}
    )
    $bad = @()
    foreach ($e in $expect) {
        $item = Get-ItemProperty -LiteralPath $e.P -ErrorAction SilentlyContinue
        $prop = if ($item) { $item.PSObject.Properties[$e.N] } else { $null }
        if (-not $prop)                    { $bad += "$($e.P)\$($e.N) missing" }
        elseif ("$($prop.Value)" -ne "$($e.V)") { $bad += "$($e.P)\$($e.N) is '$($prop.Value)', want '$($e.V)'" }
    }
    # actual log sizes as the Event Log service sees them
    $logs = @(@{L='Security';V=1048576}, @{L='Microsoft-Windows-PowerShell/Operational';V=262144},
              @{L='Microsoft-Windows-Sysmon/Operational';V=262144}, @{L='Microsoft-Windows-Windows Defender/Operational';V=262144})
    $notes = @()
    foreach ($l in $logs) {
        $info = Get-WinEvent -ListLog $l.L -ErrorAction SilentlyContinue
        if (-not $info) { $notes += "$($l.L) not present here (skipped)"; continue }
        $kb = [int64]($info.MaximumSizeInBytes / 1KB)
        if ($kb -lt $l.V) {
            if ($l.L -eq 'Security') { $bad += "Log 'Security' is $kb KB, want $($l.V) KB (another GPO may be setting it; check gpresult /h)" }
            else { $notes += "'$($l.L)' is $kb KB (startup script sets it at next boot)" }
        }
    }
    if ($bad.Count -gt 0) { throw "$($bad.Count) mismatch(es): $($bad -join '; ')" }
    "All $($expect.Count) registry policies and log sizes are in effect" + $(if ($notes) { " ($($notes -join '; '))" } else { '' })
}

# B19  GPO version is consistent (AD vs SYSVOL) and has reached every DC
Invoke-Block -Id 'B19' -Name 'Verify AD/SYSVOL version consistency and DC replication' -Verify -Prereq { Test-GpoReady } -Action {
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
    if ($lag.Count -gt 0) { throw "Not yet consistent on: $($lag -join '; '). Replication may still be in progress; re-run with -VerifyOnly in a few minutes." }
    "Version $want present in AD and SYSVOL on all $n DC(s)"
}

# =====================================================================================
# SUMMARY
# =====================================================================================
Write-Host "`n================ SUMMARY ================" -ForegroundColor White
$script:Results | Format-Table Block, Status, Name, Detail -AutoSize -Wrap
$failed = @($script:Results | Where-Object Status -eq 'FAILED').Count
$skipped = @($script:Results | Where-Object Status -eq 'SKIPPED').Count
Write-Host ("OK: {0}  SKIPPED: {1}  FAILED: {2}" -f @($script:Results | Where-Object Status -eq 'OK').Count, $skipped, $failed)
if ($LogFile) { Write-Host "Full log: $LogFile" }
try { Stop-Transcript | Out-Null } catch { }
if ($Pause) { Read-Host 'Press Enter to close' | Out-Null }
$global:LASTEXITCODE = [int]($failed -gt 0)   # exit-code style result without closing your session