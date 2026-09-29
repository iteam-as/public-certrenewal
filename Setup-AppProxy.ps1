#Requires -Version 5.1
<#
.SYNOPSIS
  One-time setup for the Entra Application Proxy certificate sync (issue #64). Run elevated by a Graph
  admin on each fleet server that publishes a cert through Application Proxy.
.DESCRIPTION
  The fourth published, signed artifact of cert-renewal v2 (sibling of Create-New-Cert.ps1). It registers
  (or reuses) the shared "AppProxy-Certificate-Updater" Entra app, mints a non-exportable auth certificate
  in LocalMachine\My, uploads its public key, grants the Graph app-roles + admin consent, and writes the
  shared AppProxyAuth block into cert-config.json. After this runs, the daily SYSTEM renewal
  (Renew-Cert.ps1) pushes each renewed cert into its Application Proxy app inline - no second scheduled
  task, no poller (the renewal already has the new thumbprint in hand). Per-domain wiring (which cert ->
  which App Proxy app) is done in Create-New-Cert.ps1's Add/Update flows.

  This is the ONLY script that touches the Microsoft Graph PowerShell SDK, and only the two sub-modules it
  needs (Microsoft.Graph.Authentication + Microsoft.Graph.Applications), installed on demand. The renewal
  and creator talk to Graph over raw cert-auth REST (no SDK) to keep the SYSTEM renewal path lean.

  Modes:
   - (default) fresh setup: register/reuse the app + auth cert, write AppProxyAuth.
   - -Migrate: adopt an existing standalone AdHoc App Proxy install (reuse its app + auth cert, map its
     AppProxies[] onto our Domains[] by certificate subject/SAN, unregister its 3:30 AM task, archive its
     scripts/config). Idempotent, best-effort, mirrors bootstrap's v1->v2 migration.
.PARAMETER DryRun
  Read-only: log what WOULD happen; no module install, no Entra writes, no cert mint, no config write,
  no task unregister.
.PARAMETER Migrate
  Adopt an existing AdHoc App Proxy install instead of a fresh registration (see -OldAppProxyConfigPath).
.PARAMETER ConfigPath
  cert-config.json to update. Defaults to this platform's layout:
  C:\Cert\Renewal\cert-config.json on Windows, /etc/certrenewal/cert-config.json on Linux.
.PARAMETER OldAppProxyConfigPath
  The AdHoc tool's config to migrate from (default C:\Cert\AppProxy\AppProxyConfig.json). -Migrate only.
.NOTES
  Source of truth : iteam-as/private-certrenewal (this repo, src/). Published (signed) to
  iteam-as/public-certrenewal by .github/workflows/release.yml on a v*.*.* tag. Do NOT edit the
  public copy by hand. It shares the platform block (Write-Log, the journald transport,
  Write-EventLogEntry, Test-IsElevated, Get-PlatformPaths, $IsWindowsHost) with the three core scripts
  BYTE-FOR-BYTE under the diff-able rule, enforced by tests/ManifestSignature.Tests.ps1 - it is the
  fourth script in that test as of #23 L3 (D10). Its own Get-CertConfig / Backup-Config / Save-Config
  deliberately do NOT match the core's: they are keyed on this script's -ConfigPath and are
  telemetry-free by design (the renewal owns the telemetry path). Event IDs: 1300-1350.
#>
[CmdletBinding()]
param(
    [switch] $DryRun,
    [switch] $Migrate,
    # Empty on purpose, resolved in Main from Get-PlatformPaths. A param() default is bound BEFORE the
    # script body runs, so it cannot call a function this script defines - the same load-order
    # constraint the core scripts hit with their path constants, seen from the other side.
    [string] $ConfigPath            = '',
    [string] $OldAppProxyConfigPath = 'C:\Cert\AppProxy\AppProxyConfig.json'
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# CI replaces 'DEV' with the release tag (e.g. 2.7.0) at publish time.
$ScriptVersion = '2.11.2'

# The shared Entra app (one per tenant) the fleet authenticates as to update App Proxy certs.
$AppName = 'AppProxy-Certificate-Updater'

# Graph SDK sub-modules - only the two we use (NOT the full Microsoft.Graph meta-module, NOT Users /
# Identity.DirectoryManagement which the AdHoc #Requires lists but our flow never calls).
$GraphModules = @('Microsoft.Graph.Authentication', 'Microsoft.Graph.Applications')

# Delegated scopes the operator's sign-in must carry: register the app, upload the cert, grant the app-role
# assignments. Verified against Get-MgContext after Connect-MgGraph (a cached token can lack them).
$RequiredGraphScopes = @('Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All', 'Directory.ReadWrite.All')

# Directory roles that may grant Microsoft Graph APPLICATION roles (the consent step). Application
# Administrator / Cloud Application Administrator explicitly cannot. Checked ACTIVE right after sign-in,
# before anything is created (#128). Keyed by roleTemplateId, which is the same in every tenant.
$RequiredDirectoryRoles = @{
    '62e90394-69f5-4237-9190-012177145e10' = 'Global Administrator'
    'e8611ab8-c189-46e8-94e1-60213ab1f814' = 'Privileged Role Administrator'
}

# The consent grant is retried on a refusal: a grant posted seconds after New-MgServicePrincipal has been
# answered with 403 Authorization_RequestDenied for a permanent Global Administrator and then succeeded from
# the portal minutes later (#128), which is what a not-yet-replicated service principal looks like. ~90 s.
$GrantRetryDelaysSeconds = @(5, 10, 15, 30, 30)

# What the operator does by hand when the grant step still fails; the rerun then finds the roles granted.
$PortalConsentFallback = "Fallback: in the Entra admin center open Enterprise applications > $AppName > Permissions > 'Grant admin consent', then run this setup again - it reuses everything already created."

# Graph app-role ids (well-known): Application.ReadWrite.All + Directory.ReadWrite.All on the Graph SP.
$GraphResourceId       = '00000003-0000-0000-c000-000000000000'
$AppReadWriteAllRole   = '1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9'
$DirectoryReadWriteAll = '19dbc75e-c2e2-444c-a770-ec69d8559fc7'

# The AdHoc install we migrate from (-Migrate).
$OldAppProxyTaskName = 'AppProxy-CertificateUpdate'

# --- Platform gate (issue #23 L3, D10) ---------------------------------------
# $IsWindows is UNDEFINED on Windows PowerShell 5.1 - it reads as $null, i.e. falsy - so the edition has to
# be tested first or every 5.1 box would decide it was running on Linux. SHARED VERBATIM (diff-able rule).
$IsWindowsHost = ($PSVersionTable.PSEdition -ne 'Core') -or [bool]$IsWindows

# Event log (Windows) / journald (Linux). The source is shared with renewal/creator/bootstrap and
# Setup-AppProxy owns 1300-1350; $ScriptComponent is the CERTRENEWAL_SCRIPT journald field, and it is the
# one constant that must DIFFER from the other three scripts' - `journalctl CERTRENEWAL_SCRIPT=appproxy-setup`.
$EventLogName   = 'Application'
$EventLogSource = 'CertRenewal'
$ScriptComponent = 'appproxy-setup'
$EID = @{ Start = 1300; AppRegistered = 1310; AuthCertMinted = 1320; ConfigWritten = 1330; Migrated = 1340; Failed = 1350 }

#region Helpers ---------------------------------------------------------------

# --- Shared platform block (issue #23 L3, D10) ------------------------------
# Everything down to Test-IsElevated is COPIED BYTE-FOR-BYTE from the core scripts (Write-Log and the
# logging family from Renew-Cert.ps1, Test-IsElevated from bootstrap.ps1, which is the only other script
# that needs it) and is ENFORCED by the byte-identity test in tests/ManifestSignature.Tests.ps1 - this
# script is the fourth one that test covers. Change a copy here and you change it in all four, or CI
# fails: the comment is the claim, the test is the enforcement.
#
# The reason this tool joined the diff-able core at all: the moment it needs a $IsWindowsHost gate, the
# alternative is a SECOND, divergent copy of the journald transport living in the least-exercised script
# in the product. Its Write-Log used to differ from the core's by one comment line - drift of exactly the
# kind this prevents, and nothing was watching.

function Get-PlatformPaths {
    # The on-disk layout for this host (spec section 2). Windows keeps the single C:\Cert\Renewal root it has
    # always had, so nothing about an existing box changes. Linux uses the split tree: /opt for the
    # self-updating vendor scripts, /etc for config an admin edits, /var/lib for state, /var/log for
    # transcripts. Every value is a DEFAULT - cert-config overrides (SharedPoshAcmePath, per-domain
    # Files.Directory) still win. Defined ABOVE the path constants on purpose: they call this at load time,
    # and a function is only callable once execution has passed its definition. SHARED VERBATIM.
    if ($IsWindowsHost) {
        $root = 'C:\Cert\Renewal'
        return [pscustomobject]@{
            ScriptsDir      = $root
            ConfigDir       = $root
            StateDir        = $root
            # Literal concatenation, not Join-Path: Join-Path resolves against the running host's
            # providers, so a 'C:\...' base THROWS on Linux ("A drive with the name 'C' does not exist").
            # Keeping this function pure means the Linux CI leg can verify the Windows layout too.
            Config          = "$root\cert-config.json"
            Secrets         = "$root\cert-secrets.json"
            SelfUpdateState = "$root\selfupdate-state.json"
            LogDir          = "$root\log"
            ConfigBackups   = "$root\config-backups"
            PoshAcmeHome    = 'C:\ProgramData\Posh-ACME'
            KeyDir          = $null    # Windows keeps machine credentials in LocalMachine\My, not as files
            LiveDir         = $null    # 'Files' deployment is Linux-only for now (D9)
        }
    }
    return [pscustomobject]@{
        ScriptsDir      = '/opt/certrenewal'
        ConfigDir       = '/etc/certrenewal'
        StateDir        = '/var/lib/certrenewal'
        Config          = '/etc/certrenewal/cert-config.json'
        Secrets         = '/etc/certrenewal/cert-secrets.json'
        SelfUpdateState = '/var/lib/certrenewal/selfupdate-state.json'
        LogDir          = '/var/log/certrenewal'
        ConfigBackups   = '/var/lib/certrenewal/config-backups'
        PoshAcmeHome    = '/var/lib/certrenewal/posh-acme'
        KeyDir          = '/etc/certrenewal/keys'
        LiveDir         = '/var/lib/certrenewal/live'
    }
}

function Write-Log {
    param(
        [Parameter(Mandatory)][string] $Message,
        [ValidateSet('INFO', 'SUCCESS', 'WARNING', 'ERROR', 'DEBUG')][string] $Level = 'INFO'
    )
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    switch ($Level) {
        'SUCCESS' { Write-Host $line -ForegroundColor Green }
        'WARNING' { Write-Host $line -ForegroundColor Yellow }
        'ERROR'   { Write-Host $line -ForegroundColor Red }
        'DEBUG'   { Write-Host $line -ForegroundColor Gray }
        default   { Write-Host $line }
    }
}

function Write-EventLogEntry {
    param(
        [Parameter(Mandatory)][int] $EventId,
        [ValidateSet('Information', 'Warning', 'Error')][string] $EntryType = 'Information',
        [Parameter(Mandatory)][string] $Message
    )
    try {
        if (-not $IsWindowsHost) {
            # journald is the Linux event log. The -t tag keeps `journalctl -t CertRenewal` working as the
            # Get-WinEvent equivalent, and the [EID nnnn] prefix preserves the IDs dashboards key on - the
            # ranges are unchanged across platforms (renewal 1000-1050, creator 1100-1150, bootstrap
            # 1200-1250, App Proxy setup 1300-1350).
            $prio = switch ($EntryType) { 'Error' { 'err' } 'Warning' { 'warning' } default { 'info' } }
            Write-JournaldEntry -Tag $EventLogSource -Priority $prio -Message "[EID $EventId] $Message" `
                -EventId $EventId -Component $ScriptComponent
            return
        }
        if (-not [System.Diagnostics.EventLog]::SourceExists($EventLogSource)) {
            New-EventLog -LogName $EventLogName -Source $EventLogSource -ErrorAction Stop
        }
        Write-EventLog -LogName $EventLogName -Source $EventLogSource -EventId $EventId -EntryType $EntryType -Message $Message -ErrorAction Stop
    }
    catch {
        # Event Log needs admin to create the source; never fatal - transcript still captures everything.
        Write-Log "Event Log write skipped (id $EventId): $($_.Exception.Message)" -Level DEBUG
    }
}

function Test-NativeCommand {
    # Is this native binary actually present? Split into its own function for a testing reason worth
    # stating: a Pester stub or mock is a FUNCTION, so a `-CommandType Application` check can never see
    # it - which would leave every transport-selection branch below unreachable in tests anywhere but a
    # real Linux box. Mocking this one predicate instead keeps the production check strict (a PowerShell
    # function called `logger` must not be mistaken for the binary) while making the branches testable.
    # SHARED VERBATIM.
    param([Parameter(Mandatory)][string] $Name)
    return [bool](Get-Command $Name -CommandType Application -ErrorAction SilentlyContinue)
}

function Get-JournaldFieldBlock {
    # The journald native-protocol field block for one entry (spec section 8), built separately from the
    # sending for a concrete reason: a Pester mock does NOT receive piped input, so a block piped straight
    # into `logger --journald` is invisible to tests. Keeping the construction pure means the FIELDS are
    # asserted directly and the native call only has to be checked for having happened.
    # SHARED VERBATIM.
    param(
        [Parameter(Mandatory)][string] $Tag,
        [Parameter(Mandatory)][ValidateSet('info', 'warning', 'err')][string] $Priority,
        [Parameter(Mandatory)][string] $Message,
        [int] $EventId,
        [string] $Component
    )
    # PRIORITY is the NUMERIC syslog level in the native protocol, not the name systemd-cat takes.
    $syslogPriority = switch ($Priority) { 'err' { 3 } 'warning' { 4 } default { 6 } }
    $fields = @("MESSAGE=$Message", "PRIORITY=$syslogPriority", "SYSLOG_IDENTIFIER=$Tag")
    # Omitted rather than emitted empty, so a consumer can filter on presence.
    if ($EventId)   { $fields += "CERTRENEWAL_EID=$EventId" }
    if ($Component) { $fields += "CERTRENEWAL_SCRIPT=$Component" }
    return ($fields -join "`n")
}

function Test-LoggerJournaldSupport {
    # Does this box's logger understand --journald? util-linux/bsdutils does; a BusyBox logger does not.
    # Probed once and cached, because Write-JournaldEntry is called many times per run and shelling out to
    # `logger --help` each time would be absurd. SHARED VERBATIM.
    if ($null -ne $script:LoggerHasJournald) { return $script:LoggerHasJournald }
    $script:LoggerHasJournald = $false
    if (Test-NativeCommand 'logger') {
        try {
            $help = & logger --help 2>&1
            $script:LoggerHasJournald = [bool](@($help) -match '--journald')
        }
        catch { $script:LoggerHasJournald = $false }
    }
    return $script:LoggerHasJournald
}

function Write-JournaldEntry {
    # The Linux half of Write-EventLogEntry, split out so the native-command fallback lives in one place and
    # so tests can mock it. Three transports, best first:
    #
    #   logger --journald  writes NATIVE journald fields, so the event id becomes something you can QUERY
    #                      (`journalctl CERTRENEWAL_EID=1030`) instead of text every consumer has to parse
    #                      back out of a message. This is what spec section 8 asks for.
    #   systemd-cat        tag + priority only, no custom fields - the systemd baseline.
    #   logger -t          plain syslog, for a container with neither of the above.
    #
    # The `[EID nnnn]` message prefix is applied by the caller and therefore appears on ALL THREE, so
    # `journalctl -t CertRenewal` reads identically however the entry got in and nothing depends on which
    # transport a given box happened to have. The structured fields are a bonus on top, never the only
    # copy of the id. Throws if it cannot log at all - the caller treats that exactly like a failed Windows
    # event-log write (DEBUG line, run continues). SHARED VERBATIM.
    param(
        [Parameter(Mandatory)][string] $Tag,
        [Parameter(Mandatory)][ValidateSet('info', 'warning', 'err')][string] $Priority,
        [Parameter(Mandatory)][string] $Message,
        [int] $EventId,
        [string] $Component
    )
    # journald's native protocol needs a length-prefixed binary blob for any value containing a newline.
    # Folding to spaces keeps MESSAGE identical across all three transports and loses nothing that matters
    # in a one-line event entry (the transcript keeps the full text either way).
    $flat = ($Message -replace '\r?\n', ' ').Trim()

    if (Test-LoggerJournaldSupport) {
        Get-JournaldFieldBlock -Tag $Tag -Priority $Priority -Message $flat -EventId $EventId -Component $Component |
            & logger --journald
        if ($LASTEXITCODE -eq 0) { return }
    }
    if (Test-NativeCommand 'systemd-cat') {
        $flat | & systemd-cat -t $Tag -p $Priority
        if ($LASTEXITCODE -eq 0) { return }
    }
    if (Test-NativeCommand 'logger') {
        & logger -t $Tag -p "user.$Priority" -- $flat
        if ($LASTEXITCODE -eq 0) { return }
    }
    throw 'no journald or syslog transport could record the entry'
}

function Get-CredentialRefName {
    # Which credential field this platform actually reads: a thumbprint into LocalMachine\My on Windows,
    # a PEM path on Linux (D5). The config-validation guards use this so a block carrying only the OTHER
    # platform's field is reported as incomplete for THIS one, instead of either field silently passing.
    # SHARED VERBATIM across Renew-Cert / Create-New-Cert / bootstrap (diff-able rule).
    param([string] $ThumbprintField = 'CertThumbprint', [string] $PathField = 'CertPath')
    if ($IsWindowsHost) { return $ThumbprintField }
    return $PathField
}

function Set-RestrictedFileAccess {
    # Lock a secrets file down to the identity the unattended run uses: Administrators + SYSTEM on Windows
    # (SIDs, not names, for locale independence), 0600 root:root on Linux. chmod/chown rather than
    # [IO.File]::SetUnixFileMode: .NET has no ownership API at all, so chown is needed whichever way the mode
    # is set, and one mechanism for both beats two. Never fatal on either platform - a failure is logged and
    # the run continues, as it always has.
    # SHARED VERBATIM.
    param([Parameter(Mandatory)][string] $Path)
    try {
        if (-not $IsWindowsHost) {
            & chmod 0600 -- $Path
            if ($LASTEXITCODE -ne 0) { throw "chmod 0600 exited $LASTEXITCODE" }
            # chown only does anything as root, which the systemd unit always is. A non-root context (a test,
            # an operator poking at it) legitimately cannot chown, and 0600 has already done the real work.
            & chown root:root -- $Path 2>$null
            if ($LASTEXITCODE -ne 0) { Write-Log "  chown root:root skipped on ${Path} (not root)." -Level DEBUG }
            else { Write-Log "  Restricted $Path to 0600 root:root." -Level DEBUG }
            return
        }
        $adminSid  = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')   # BUILTIN\Administrators
        $systemSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')        # NT AUTHORITY\SYSTEM
        $acl = New-Object System.Security.AccessControl.FileSecurity
        $acl.SetAccessRuleProtection($true, $false)   # protect from inheritance, drop inherited rules
        foreach ($sid in $adminSid, $systemSid) {
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                $sid, 'FullControl', 'Allow')))
        }
        $acl.SetOwner($adminSid)
        Set-Acl -Path $Path -AclObject $acl
        Write-Log "  Restricted ACL on cert-secrets.json (Administrators + SYSTEM only)." -Level DEBUG
    }
    catch { Write-Log "Could not restrict access on ${Path}: $($_.Exception.Message)" -Level WARNING }
}

function Test-HostInteractive {
    # Is there actually a human on the other end of stdin?
    #
    # [Environment]::UserInteractive is NOT the answer on Linux: .NET hardcodes it to $true there, so
    # it stays $true under systemd, cron, Ansible, cloud-init, a container, or any plain
    # `sh install.sh < /dev/null`. Every prompt gate built on it alone was therefore dead on Linux,
    # and Read-Host went on to return $null at EOF - which surfaced as "You cannot call a method on a
    # null-valued expression", instead of the clear "supply -Abr/-InvoiceCode" message the
    # non-interactive branch exists to give.
    #
    # [Console]::IsInputRedirected is the portable half: $false only when stdin is a real terminal.
    # BOTH are needed - a Windows service reports UserInteractive $false with stdin not redirected,
    # and a Linux terminal reports UserInteractive $true with stdin not redirected. SHARED VERBATIM by
    # the creator + bootstrap; the renewal runs unattended and never prompts, so it has no copy.
    if (-not [Environment]::UserInteractive) { return $false }
    try { return (-not [Console]::IsInputRedirected) }
    catch { return $false }   # no console at all (a hosted runspace): treat as unattended
}

function Test-IsElevated {
    # True when this process can do the privileged work: LocalMachine cert stores, machine-wide modules,
    # the scheduled task / systemd units, and the event source. On Linux that is simply uid 0 - the systemd
    # unit runs as root and the whole /opt /etc /var layout is root-owned.
    if (-not $IsWindowsHost) { return ([int](& id -u) -eq 0) }
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($id)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

# --- Console UI -------------------------------------------------------------
# The same presentation layer as Create-New-Cert.ps1 so the two interactive tools read alike: headers +
# rules for section boundaries, aligned 'label ...... value' info rows, and Ok/Note/Warn inline feedback.
# Helpers are COPIED VERBATIM from the creator (Get-UiGlyph / Write-UiRule / Write-UiHeader / Write-UiField /
# Write-UiSetting / Write-UiOption / Write-UiResult / Read-UiInput) - keep them byte-identical if the creator's
# change. Rules/glyphs use Unicode on a UTF-8 console, ASCII elsewhere ($script:UiUnicode set in Main).

function Get-UiGlyph {
    param([Parameter(Mandatory)][ValidateSet('Rule', 'Ok', 'Arrow', 'Dot')][string] $Name)
    $uni = ($script:UiUnicode -eq $true)
    switch ($Name) {
        'Rule'  { if ($uni) { [string][char]0x2500 } else { '-' } }
        'Ok'    { if ($uni) { [string][char]0x2713 } else { '[ok]' } }
        'Arrow' { if ($uni) { [string][char]0x2192 } else { '->' } }
        'Dot'   { if ($uni) { [string][char]0x00B7 } else { '-' } }
    }
}

function Write-UiRule {
    param([int] $Width = 64)
    Write-Host (' ' + ((Get-UiGlyph Rule) * $Width)) -ForegroundColor DarkCyan
}

function Write-UiHeader {
    param([Parameter(Mandatory)][string] $Title)
    Write-Host ''
    Write-Host " $Title" -ForegroundColor Cyan
    Write-UiRule
}

function Write-UiField {
    # Aligned 'label ...... value' information row; the value column is fixed so values line up regardless of
    # label length. Empty value renders as (none).
    param([Parameter(Mandatory)][string] $Label, [string] $Value, [int] $LabelWidth = 20)
    if ([string]::IsNullOrEmpty($Value)) { $Value = '(none)' }
    $leader = "{0} {1}" -f $Label, ('.' * [Math]::Max(3, ($LabelWidth - $Label.Length)))
    Write-Host ("   {0} " -f $leader.PadRight($LabelWidth + 2)) -ForegroundColor DarkGray -NoNewline
    Write-Host $Value -ForegroundColor White
}

function Write-UiSetting {
    # Sub-heading naming the thing being decided; -Current (when bound) shows the existing value.
    param([Parameter(Mandatory)][string] $Name, [string] $Current)
    Write-Host ''
    if ($PSBoundParameters.ContainsKey('Current')) {
        $shown = if ([string]::IsNullOrWhiteSpace($Current)) { 'none' } else { $Current }
        Write-Host " $Name" -ForegroundColor White -NoNewline
        Write-Host "   (current: $shown)" -ForegroundColor DarkGray
    }
    else { Write-Host " $Name" -ForegroundColor White }
}

function Write-UiOption {
    # The available choices for the current question (keys called out).
    param([Parameter(Mandatory)][string] $Text)
    Write-Host "   $Text" -ForegroundColor DarkYellow
}

function Write-UiResult {
    # Inline feedback after an answer: Ok (check), Note (arrow, dim), Warn (arrow, yellow).
    param([Parameter(Mandatory)][string] $Text, [ValidateSet('Ok', 'Note', 'Warn')][string] $Kind = 'Note')
    switch ($Kind) {
        'Ok'   { Write-Host ("   {0} {1}" -f (Get-UiGlyph Ok), $Text) -ForegroundColor Green }
        'Warn' { Write-Host ("   {0} {1}" -f (Get-UiGlyph Arrow), $Text) -ForegroundColor Yellow }
        default { Write-Host ("   {0} {1}" -f (Get-UiGlyph Arrow), $Text) -ForegroundColor DarkGray }
    }
}

function Read-UiInput {
    # The single question primitive: ' > ' marks "type something now". -Default (when non-empty) is shown in
    # brackets. Returns the raw string (callers trim/parse). Goes through Read-Host so prompts stay mockable.
    param([Parameter(Mandatory)][string] $Prompt, [string] $Default)
    $label = if ($PSBoundParameters.ContainsKey('Default') -and $Default -ne '') { "$Prompt [$Default]" } else { $Prompt }
    return (Read-Host " >  $label")
}

function Get-CertConfig {
    if (-not (Test-Path $ConfigPath)) { throw "cert-config.json not found at $ConfigPath (run bootstrap / Create-New-Cert.ps1 first)" }
    try { return Get-Content $ConfigPath -Raw | ConvertFrom-Json }
    catch { throw "cert-config.json is not valid JSON: $($_.Exception.Message)" }
}

function Backup-Config {
    # Snapshot the current cert-config.json before overwrite, into <config dir>\config-backups\ as
    # cert-config.<timestamp>.<reason>.json (newest 20 kept) - the SAME convention the creator/renewal use
    # (Backup-CertConfig), so all backups live in one place. Best-effort; no-op when the file is absent.
    param([string] $Reason = 'AppProxy setup')
    try {
        if (-not (Test-Path -LiteralPath $ConfigPath)) { return }
        $backupDir = Join-Path (Split-Path -Parent $ConfigPath) 'config-backups'
        if (-not (Test-Path -LiteralPath $backupDir)) { New-Item -ItemType Directory -Path $backupDir -Force | Out-Null }
        $slug = ($Reason -replace '[^A-Za-z0-9]+', '-').Trim('-'); if (-not $slug) { $slug = 'save' }
        $dest = Join-Path $backupDir ('cert-config.{0}.{1}.json' -f (Get-Date -Format 'yyyy-MM-dd-HH_mm_ss_fff'), $slug)
        Copy-Item -LiteralPath $ConfigPath -Destination $dest -Force
        Write-Log "Backed up previous cert-config.json -> $dest" -Level DEBUG
        Get-ChildItem -LiteralPath $backupDir -Filter 'cert-config.*.json' -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -Skip 20 |
            Remove-Item -Force -ErrorAction SilentlyContinue
    }
    catch { Write-Log "Could not back up cert-config.json: $($_.Exception.Message)" -Level DEBUG }
}

function Save-Config {
    # Persist the (mutated) cert-config object. DryRun-gated; snapshots the previous file to config-backups\
    # first (best-effort, via Backup-Config). Telemetry-free by design - the renewal owns the telemetry
    # path; this is interactive admin tooling.
    param([Parameter(Mandatory)][object] $Config, [string] $Reason = 'AppProxy setup')
    if ($DryRun) { Write-Log "[DryRun] WOULD save cert-config.json ($Reason)." -Level INFO; return }
    try {
        Backup-Config -Reason $Reason
        $Config | ConvertTo-Json -Depth 10 | Out-File -FilePath $ConfigPath -Force -Encoding UTF8
        Write-Log "cert-config.json saved ($Reason)." -Level SUCCESS
        Write-EventLogEntry $EID.ConfigWritten Information "cert-config.json updated by Setup-AppProxy ($Reason)"
    }
    catch { throw "Failed to save cert-config.json: $($_.Exception.Message)" }
}

function Install-GraphModules {
    # Ensure the two Graph sub-modules we use are present (machine-wide so any admin context can load them).
    # On demand, mirroring bootstrap's Install-RequiredModules. DryRun-gated.
    if ($DryRun) { Write-Log "[DryRun] WOULD ensure NuGet + PSGallery trust + install (AllUsers): $($GraphModules -join ', ')." -Level INFO; return }
    try {
        # The NuGet PACKAGE PROVIDER is a PowerShellGet-v2-on-Windows concern; pwsh on Linux ships a
        # PSGallery that needs no provider bootstrap, and Get-PackageProvider may not even be present.
        # Same gate, same reason, as bootstrap.ps1's Install-RequiredModules (D11).
        if ($IsWindowsHost -and -not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
            Write-Log 'Installing NuGet package provider...' -Level INFO
            Install-PackageProvider -Name NuGet -MinimumVersion '2.8.5.201' -Force -Scope AllUsers | Out-Null
        }
        if ((Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue).InstallationPolicy -ne 'Trusted') {
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
        }
    }
    catch { Write-Log "Package provider / repository prep had a problem: $($_.Exception.Message). Continuing." -Level WARNING }

    foreach ($m in $GraphModules) {
        if (Get-Module -ListAvailable -Name $m) { Write-Log "  Module '$m' already installed." -Level DEBUG; continue }
        Write-Log "Installing module '$m' (AllUsers)..." -Level INFO
        Install-Module -Name $m -Scope AllUsers -Force -AllowClobber -ErrorAction Stop | Out-Null
        Write-Log "  Installed '$m'." -Level SUCCESS
    }
    foreach ($m in $GraphModules) { Import-Module $m -ErrorAction Stop }
}

function Test-IsGuid {
    # True when the value is a GUID. Used wherever an id from Graph is about to be persisted or reused, so a
    # $null from a failed call (or a leaked banner) is caught at the boundary instead of days later.
    param([AllowNull()][AllowEmptyString()][string] $Value)
    return [bool]($Value -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')
}

function Get-MissingGraphScopes {
    # The required scopes that the signed-in context does NOT carry (case-insensitive). Empty = all present.
    param([AllowNull()][string[]] $GrantedScopes, [Parameter(Mandatory)][string[]] $RequiredScopes)
    $granted = @($GrantedScopes | ForEach-Object { ([string]$_).ToLowerInvariant() })
    return @($RequiredScopes | Where-Object { $granted -notcontains $_.ToLowerInvariant() })
}

function Test-HasRequiredDirectoryRole {
    # True when at least one ACTIVE role template id is a role that can grant Graph application roles.
    param([AllowNull()][string[]] $ActiveRoleTemplateIds, [Parameter(Mandatory)][hashtable] $RequiredRoles)
    foreach ($id in @($ActiveRoleTemplateIds)) {
        if ($id -and $RequiredRoles.ContainsKey(([string]$id).ToLowerInvariant())) { return $true }
    }
    return $false
}

function Get-ActiveDirectoryRoles {
    # The signed-in account's ACTIVE directory roles as @(@{ TemplateId; DisplayName }), read through
    # transitiveMemberOf so a role held via a role-assignable group counts and a PIM role counts only while
    # it is activated. Uses the raw request cmdlet from the Authentication module (no Users module) and the
    # Directory.ReadWrite.All scope already requested. Returns $null when the read itself fails: this is a
    # pre-flight diagnostic and must not hide the real step's error behind its own.
    $roles = @()
    $uri = 'https://graph.microsoft.com/v1.0/me/transitiveMemberOf/microsoft.graph.directoryRole?$select=roleTemplateId,displayName'
    try {
        while ($uri) {
            $page = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            $roles += @(@($page.value) | ForEach-Object { @{ TemplateId = [string]$_.roleTemplateId; DisplayName = [string]$_.displayName } })
            $uri = [string]$page.'@odata.nextLink'
        }
    }
    catch {
        Write-Log "Could not read the signed-in account's directory roles ($(@(([string]$_.Exception.Message) -split '\r?\n')[0])). Continuing without the pre-flight role check." -Level WARNING
        return $null
    }
    return ,$roles
}

function ConvertTo-GraphFailureMessage {
    # One line the operator can act on. A 403 Authorization_RequestDenied from a Graph call means Entra
    # refused the SIGNED-IN ACCOUNT for that operation - the delegated scope only lets the user do what the
    # user could already do. Say which role that takes and the one token trap (a role activated through
    # PIM after the sign-in), instead of leaving the operator staring at "Insufficient privileges".
    param([Parameter(Mandatory)][string] $Step, [Parameter(Mandatory)][System.Management.Automation.ErrorRecord] $ErrorRecord)
    $detail = [string]$ErrorRecord.Exception.Message
    $msg = "$Step failed: $(@($detail -split '\r?\n')[0])"   # first line only - the SDK appends status + headers
    if ($detail -match 'Authorization_RequestDenied|Insufficient privileges' -or [string]$ErrorRecord.FullyQualifiedErrorId -like 'Authorization_RequestDenied*') {
        $msg += ' Entra refused the signed-in account for this operation. Granting Microsoft Graph application roles' +
                ' needs an ACTIVE Global Administrator or Privileged Role Administrator role in the session this setup' +
                ' signed in with (Application Administrator / Cloud Application Administrator cannot). A role activated' +
                ' through PIM after the sign-in is not in the token: run Disconnect-MgGraph, then run this setup again.'
    }
    return $msg
}

function Connect-SetupGraph {
    # Interactive Graph sign-in for the admin running setup. Returns the tenant id. The scopes are the ones
    # needed to register the app, upload the cert, and grant the app-role assignments.
    #
    # NOT named Connect-Graph (#131): Microsoft.Graph.Authentication exports Connect-Graph as an ALIAS of
    # Connect-MgGraph, and PowerShell resolves an alias before a function. From the moment
    # Install-GraphModules imported the SDK, Main's call ran a bare Connect-MgGraph - no scopes, no
    # device code, the on-disk token cache instead of -ContextScope Process - and not one line of this
    # function: the tenant-id guard, the scope guard (#117) and the active-role pre-flight (#128) had
    # never executed in production since v2.7.0. On Linux it waited 120 s for a browser that does not
    # exist. The Pester harness dot-sources functions without importing the SDK, so every test called
    # the real function; tests/Setup-AppProxy.Tests.ps1 now checks every name here against the SDK's
    # exports.
    if ($DryRun) { Write-Log "[DryRun] WOULD Connect-MgGraph ($($RequiredGraphScopes -join ', '))." -Level INFO; return $null }
    # The device-code flow prints a code the operator has to type somewhere else, so a non-interactive
    # Linux session (a pipe, a unit, a CI step) would hang on a prompt nobody can see. Refuse clearly
    # instead. [Environment]::UserInteractive is hard-coded $true on Unix, which is why this goes
    # through the shared Test-HostInteractive.
    if (-not $IsWindowsHost -and -not (Test-HostInteractive)) {
        throw 'Setup-AppProxy needs an interactive terminal on Linux: the sign-in prints a device code you have to enter on your workstation. Run it from a terminal (ssh -t ...), not from a pipe, a script or a unit.'
    }
    # Suppress the SDK's welcome / connection banner on EVERY stream it might use: -NoWelcome is honored
    # inconsistently across Graph SDK versions, and the banner has been observed on the Information stream
    # (6) AND the success stream. Redirect both (6>$null + Out-Null) and silence Information at the source
    # (-InformationAction); -ErrorAction Stop still throws because the error stream is NOT redirected.
    # Without this the banner leaked into this function's output and got saved as AppProxyAuth.TenantId,
    # producing an "Invalid URL" 400 when the renewal built the token endpoint from it.
    # -ContextScope Process: the admin's token lives in this process only - never reused from (or left in)
    # the on-disk cache of an earlier session on the server, which is how a stale token gets a 403.
    #
    # D11: a Linux fleet server is administered over SSH and has no browser, so it signs in with the
    # DEVICE CODE flow - the SDK prints a code and a URL for the admin to complete on their own
    # workstation. That line must reach the operator, and the SDK (2.40, measured) writes it to the
    # SUCCESS stream - the same stream the Windows branch discards with `| Out-Null`. Doing that here
    # too is #131: the code went nowhere and the sign-in timed out after the SDK's fixed 120 seconds with
    # nothing on screen. So on that branch the stream is forwarded to the HOST: the code appears the
    # moment it is issued (the pipeline streams while Connect-MgGraph is still waiting), and nothing
    # reaches this function's return value. Any banner is shown too, which is cosmetic; Main reads the
    # tenant id off Get-MgContext rather than off the return value precisely because it cannot be trusted.
    # -ClientTimeout does NOT extend the 120 seconds (measured), hence the note saying how long there is.
    # Written as two full calls rather than a splat on purpose: every Graph SDK call in this script has
    # to carry a visible -ErrorAction (#117), and a splatted one hides it from the check that enforces it.
    if ($IsWindowsHost) {
        Connect-MgGraph -Scopes $RequiredGraphScopes -ContextScope Process `
            -NoWelcome -ErrorAction Stop -InformationAction SilentlyContinue 6>$null | Out-Null
    }
    else {
        Write-UiResult 'no browser on this host - signing in with a device code. Open the URL below on your workstation and enter the code within 2 minutes.' -Kind Note
        Connect-MgGraph -Scopes $RequiredGraphScopes -ContextScope Process -UseDeviceCode `
            -NoWelcome -ErrorAction Stop | ForEach-Object { Write-Host ('   {0}' -f $_) -ForegroundColor Yellow }
    }
    $ctx = Get-MgContext -ErrorAction Stop
    if (-not $ctx) { throw 'Connect-MgGraph did not establish a context.' }
    # Guard: the tenant id is written into cert-config.json and used to build the AAD token URL, so it MUST
    # be a GUID. If Get-MgContext ever returns something else, fail loudly rather than persist a bad value.
    $tid = [string]$ctx.TenantId
    if (-not (Test-IsGuid $tid)) {
        throw "Get-MgContext returned an unexpected tenant id ('$tid') - aborting rather than writing a bad AppProxyAuth.TenantId."
    }
    # Guard: the token must actually carry every scope we asked for. Otherwise the first mutation gets a 403
    # that reads like a role problem when it is a consent/token problem.
    $missing = Get-MissingGraphScopes -GrantedScopes $ctx.Scopes -RequiredScopes $RequiredGraphScopes
    if ($missing.Count -gt 0) {
        throw "The Graph sign-in does not carry the scope(s) $($missing -join ', '). This tenant has not consented them to 'Microsoft Graph Command Line Tools' (the app Connect-MgGraph signs in as). A Global Administrator grants that once per tenant: Entra admin center > Enterprise applications > Microsoft Graph Command Line Tools > Permissions > 'Grant admin consent' - then run this setup again."
    }
    Write-UiResult "connected as $($ctx.Account) (tenant $tid)" -Kind Ok
    # Guard (#128): the consent step assigns Microsoft Graph application roles, which only an ACTIVE Global
    # Administrator / Privileged Role Administrator may do. Find out now, before anything has been created,
    # instead of four writes later. The roles and scopes go to the log so a refusal report is conclusive.
    $activeRoles = Get-ActiveDirectoryRoles
    if ($null -ne $activeRoles) {
        $names = if ($activeRoles.Count) { @($activeRoles | ForEach-Object { $_.DisplayName }) -join ', ' } else { '(none)' }
        Write-Log "Signed in as $($ctx.Account). Active directory roles: $names. Token scopes: $($ctx.Scopes -join ' ')." -Level INFO
        if (-not (Test-HasRequiredDirectoryRole -ActiveRoleTemplateIds @($activeRoles | ForEach-Object { $_.TemplateId }) -RequiredRoles $RequiredDirectoryRoles)) {
            throw "The signed-in account ($($ctx.Account)) has no ACTIVE Global Administrator or Privileged Role Administrator role (active: $names). Those are the only roles that can grant the Microsoft Graph application roles this setup needs. Activate the role first (PIM), then run this setup again - nothing has been created."
        }
        Write-UiResult "active role allows granting Graph application roles ($names)" -Kind Ok
    }
    return $tid
}

function Get-AuthCertPemPath {
    # WHICH credential file this box is on (D12). keys/ is 0700 and is created and re-asserted by
    # bootstrap's Initialize-InstallLayout - this tool does not create it, so a box that never ran
    # bootstrap is told to run bootstrap rather than quietly getting a directory with the wrong mode.
    #
    # The CONFIG wins over the default name whenever it points at a file that is really there, because
    # the renewal's zero-touch rotation (L3c/D13) mints appproxy-auth-<yyyyMMdd>.pem BESIDE the original
    # and repoints AuthCertPath at it. Reading the default name after a rotation would mean a re-run of
    # this tool inspected a SUPERSEDED credential, minted over the file the rotation kept as its
    # rollback, uploaded a third public key, and pointed the config back at the old filename.
    param([AllowEmptyString()][string] $ConfiguredPath = '')
    $keyDir = (Get-PlatformPaths).KeyDir
    if (-not (Test-Path -LiteralPath $keyDir)) {
        throw "Key directory $keyDir does not exist - run bootstrap.ps1 (or sh install.sh) on this host first; it creates the 0700 keys/ directory this credential belongs in."
    }
    if (-not [string]::IsNullOrWhiteSpace($ConfiguredPath) -and (Test-Path -LiteralPath $ConfiguredPath)) {
        return $ConfiguredPath
    }
    return (Join-Path $keyDir 'appproxy-auth.pem')
}

function New-AuthCertificatePem {
    # The portable half of D12: mint the auth credential with .NET CertificateRequest and write it as a
    # PEM, because Linux has no machine certificate store to put it in. Same shape as the Windows mint -
    # RSA 2048, SHA-256, clientAuth EKU (1.3.6.1.5.5.7.3.2), two years - so the two platforms age
    # identically and one rotation threshold fits both.
    #
    # The CERTIFICATE goes FIRST in the file, then the PKCS#8 key: CreateFromPemFile takes the FIRST
    # certificate it finds, and bootstrap already documents that trap for telemetry-sp.pem. Written
    # temp-then-move inside the same directory (atomic, never briefly world-readable) and locked 0600
    # root:root by the shared Set-RestrictedFileAccess - no new helper, and the same mode as every other
    # credential on the box.
    #
    # Returns the RELOADED certificate, so the caller cannot tell the two platforms apart: everything
    # downstream (thumbprint, GetCertHash, Export) works on an X509Certificate2 either way.
    param([Parameter(Mandatory)][string] $Path, [Parameter(Mandatory)][string] $Subject)
    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    try {
        $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            $Subject, $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $eku = New-Object System.Security.Cryptography.OidCollection
        $null = $eku.Add((New-Object System.Security.Cryptography.Oid '1.3.6.1.5.5.7.3.2'))
        $req.CertificateExtensions.Add(
            (New-Object System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension $eku, $false))
        # Backdated five minutes: a fresh certificate whose NotBefore is in the future is rejected by the
        # token endpoint on a box whose clock runs slightly behind Entra's.
        $now  = [DateTimeOffset]::UtcNow
        $cert = $req.CreateSelfSigned($now.AddMinutes(-5), $now.AddYears(2))
        $pem  = $cert.ExportCertificatePem() + "`n" + $rsa.ExportPkcs8PrivateKeyPem() + "`n"
        $tmp  = "$Path.tmp"
        [System.IO.File]::WriteAllText($tmp, $pem)
        Set-RestrictedFileAccess -Path $tmp
        Move-Item -LiteralPath $tmp -Destination $Path -Force
        Set-RestrictedFileAccess -Path $Path
        return [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPemFile($Path)
    }
    finally { $rsa.Dispose() }
}

function Get-OrCreateAuthCertificate {
    # Mint (or reuse) the auth credential in whatever form this platform keeps one (D12): a non-exportable
    # cert in LocalMachine\My on Windows, a 0600 root:root PEM on Linux. Reuses an existing credential
    # with more than 30 days left on either - the same threshold the renewal's zero-touch rotation uses,
    # so a re-run right after a rotation does not mint a third credential. DryRun returns $null.
    #
    # -Config is read on Linux only, for AppProxyAuth.AuthCertPath: it is the one place that knows which
    # file this box is on after a rotation renamed it. Windows needs no equivalent - its reuse search
    # filters the whole store by subject and expiry, so a rotated certificate is found either way. The
    # certificate comes back carrying a CredentialPath note property, so the caller records the file that
    # was actually used instead of re-deriving a path a mint-beside has just invalidated.
    param([object] $Config)
    if (-not $IsWindowsHost) {
        $configured = if ($Config -and $Config.AppProxyAuth) { [string]$Config.AppProxyAuth.AuthCertPath } else { '' }
        $pemPath = Get-AuthCertPemPath -ConfiguredPath $configured
        $subject = "CN=$AppName-Auth"
        if ($DryRun) { Write-Log "[DryRun] WOULD mint/reuse the auth credential $subject at $pemPath (RSA 2048, clientAuth, 2y, 0600 root:root)." -Level INFO; return $null }
        if (Test-Path -LiteralPath $pemPath) {
            try {
                $existing = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPemFile($pemPath)
                if ($existing.NotAfter -gt (Get-Date).AddDays(30)) {
                    Write-UiResult "reusing existing auth credential $($existing.Thumbprint) at $pemPath (expires $($existing.NotAfter.ToString('yyyy-MM-dd')))" -Kind Ok
                    $existing | Add-Member -NotePropertyName 'CredentialPath' -NotePropertyValue $pemPath -Force
                    return $existing
                }
                Write-UiResult "the auth credential at $pemPath expires $($existing.NotAfter.ToString('yyyy-MM-dd')) - minting a replacement" -Kind Note
            }
            catch {
                # An unreadable or malformed PEM is not a reason to stop: it is a reason to replace it. The
                # old public key stays on the Entra app either way, so nothing is lost by minting.
                Write-Log "Could not read the existing auth credential at ${pemPath}: $($_.Exception.Message). Minting a new one." -Level WARNING
            }
            # Replacing something that is still on disk: mint BESIDE it, under the same dated name the
            # rotation uses, and leave the old file alone. Overwriting would destroy the rollback and -
            # because the filename would not change - leave nothing on disk saying anything happened.
            $pemPath = Join-Path (Split-Path -Parent $pemPath) ('appproxy-auth-{0}.pem' -f (Get-Date -Format 'yyyyMMdd'))
        }
        Write-UiResult "minting a new auth credential ($subject, 2 years) at $pemPath..." -Kind Note
        $cert = New-AuthCertificatePem -Path $pemPath -Subject $subject
        Write-UiResult "minted auth credential $($cert.Thumbprint) (expires $($cert.NotAfter.ToString('yyyy-MM-dd')))" -Kind Ok
        Write-EventLogEntry $EID.AuthCertMinted Information "App Proxy auth credential minted ($($cert.Thumbprint)) at $pemPath"
        $cert | Add-Member -NotePropertyName 'CredentialPath' -NotePropertyValue $pemPath -Force
        return $cert
    }
    if ($DryRun) { Write-Log "[DryRun] WOULD mint/reuse the auth certificate CN=$AppName-Auth in LocalMachine\My (non-exportable, 2y)." -Level INFO; return $null }
    $subject = "CN=$AppName-Auth"
    $existing = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue | Where-Object {
        $_.Subject -eq $subject -and $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date).AddDays(30)
    } | Sort-Object NotAfter -Descending | Select-Object -First 1
    if ($existing) {
        Write-UiResult "reusing existing auth cert $($existing.Thumbprint) (expires $($existing.NotAfter.ToString('yyyy-MM-dd')))" -Kind Ok
        return $existing
    }
    Write-UiResult "minting a new non-exportable auth cert ($subject, 2 years)..." -Kind Note
    $cert = New-SelfSignedCertificate -Subject $subject -CertStoreLocation 'Cert:\LocalMachine\My' `
        -KeyExportPolicy NonExportable -KeySpec Signature -KeyLength 2048 -KeyAlgorithm RSA -HashAlgorithm SHA256 `
        -NotAfter (Get-Date).AddYears(2) -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.2') `
        -Provider 'Microsoft Enhanced RSA and AES Cryptographic Provider'
    Write-UiResult "minted auth cert $($cert.Thumbprint) (expires $($cert.NotAfter.ToString('yyyy-MM-dd')))" -Kind Ok
    Write-EventLogEntry $EID.AuthCertMinted Information "App Proxy auth cert minted ($($cert.Thumbprint))"
    return $cert
}

function Get-OrCreateEntraApp {
    # Register (or reuse) the shared AppProxy-Certificate-Updater app, upload the auth cert's PUBLIC key,
    # add the Graph app-roles, and grant admin consent. Returns @{ AppId; ObjectId }. Lifted from the AdHoc
    # Get-OrCreateEntraApp (Graph SDK). DryRun returns a placeholder.
    param([System.Security.Cryptography.X509Certificates.X509Certificate2] $AuthCertificate)
    if ($DryRun) {
        Write-Log "[DryRun] WOULD register/reuse Entra app '$AppName', upload the auth cert, and grant Application.ReadWrite.All + Directory.ReadWrite.All." -Level INFO
        return @{ AppId = '(dry-run)'; ObjectId = '(dry-run)' }
    }

    # Every Graph mutation below carries an explicit -ErrorAction Stop and a try/catch. The Graph SDK cmdlets
    # do NOT reliably honour the script-wide $ErrorActionPreference: without this a 403 on New-MgApplication
    # returned $null, the UI printed "[ok] registered app (appId )", and the run limped on into a
    # parameter-binding error two calls later (#117). Fail closed at the call that failed, with a message
    # that names the step.
    $app = Get-MgApplication -Filter "displayName eq '$AppName'" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($app) {
        Write-UiResult "reusing existing Entra app '$AppName' (appId $($app.AppId))" -Kind Ok
    }
    else {
        Write-UiResult "registering new Entra app '$AppName'..." -Kind Note
        try { $app = New-MgApplication -DisplayName $AppName -SignInAudience 'AzureADMyOrg' -ErrorAction Stop }
        catch { throw (ConvertTo-GraphFailureMessage -Step "Registering the Entra app '$AppName'" -ErrorRecord $_) }
        Write-UiResult "registered app (appId $($app.AppId))" -Kind Ok
    }
    # The app's ids are reused by every call below and the appId is persisted as AppProxyAuth.ClientId, so
    # both must be GUIDs - never continue with an empty application.
    if (-not (Test-IsGuid ([string]$app.AppId)) -or -not (Test-IsGuid ([string]$app.Id))) {
        throw "Graph returned no usable ids for the Entra app '$AppName' (appId '$($app.AppId)', objectId '$($app.Id)') - aborting."
    }

    $sp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'" -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $sp) {
        try { $sp = New-MgServicePrincipal -AppId $app.AppId -ErrorAction Stop }
        catch { throw (ConvertTo-GraphFailureMessage -Step "Creating the service principal for '$AppName'" -ErrorRecord $_) }
        Write-UiResult 'created service principal' -Kind Note
    }
    if (-not (Test-IsGuid ([string]$sp.Id))) { throw "Graph returned no usable service principal id for '$AppName' - aborting." }

    # Upload the auth cert public key (append if not already present).
    $hash = [System.Convert]::ToBase64String($AuthCertificate.GetCertHash())
    $already = $app.KeyCredentials | Where-Object { $_.CustomKeyIdentifier -and [System.Convert]::ToBase64String($_.CustomKeyIdentifier) -eq $hash }
    if ($already) {
        Write-UiResult 'auth certificate already registered on the app' -Kind Note
    }
    else {
        $keyCred = @{
            Type        = 'AsymmetricX509Cert'
            Usage       = 'Verify'
            Key         = $AuthCertificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
            DisplayName = "Auth-Cert-$($AuthCertificate.Thumbprint.Substring(0,8))"
        }
        try { Update-MgApplication -ApplicationId $app.Id -KeyCredentials @(@($app.KeyCredentials) + $keyCred) -ErrorAction Stop }
        catch { throw (ConvertTo-GraphFailureMessage -Step 'Uploading the auth certificate to the app' -ErrorRecord $_) }
        Write-UiResult "uploaded auth certificate $($AuthCertificate.Thumbprint) to the app" -Kind Ok
    }

    # Ensure the required Graph permissions are declared.
    try {
        Update-MgApplication -ApplicationId $app.Id -ErrorAction Stop -RequiredResourceAccess @(@{
            ResourceAppId  = $GraphResourceId
            ResourceAccess = @(
                @{ Id = $AppReadWriteAllRole;   Type = 'Role' },
                @{ Id = $DirectoryReadWriteAll; Type = 'Role' }
            )
        })
    }
    catch { throw (ConvertTo-GraphFailureMessage -Step 'Declaring the required Graph permissions on the app' -ErrorRecord $_) }

    # Grant admin consent (idempotent: skip a role already assigned). This is the step that needs Global
    # Administrator / Privileged Role Administrator: it assigns Microsoft Graph application roles.
    try { $graphSp = Get-MgServicePrincipal -Filter "appId eq '$GraphResourceId'" -ErrorAction Stop | Select-Object -First 1 }
    catch { throw (ConvertTo-GraphFailureMessage -Step 'Looking up the Microsoft Graph service principal' -ErrorRecord $_) }
    if (-not (Test-IsGuid ([string]$graphSp.Id))) { throw 'The Microsoft Graph service principal was not found in this tenant - cannot grant the app-roles.' }
    $existingAssignments = @(Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -ErrorAction SilentlyContinue)
    foreach ($roleId in @($AppReadWriteAllRole, $DirectoryReadWriteAll)) {
        if ($existingAssignments | Where-Object { $_.AppRoleId -eq $roleId -and $_.ResourceId -eq $graphSp.Id }) {
            Write-UiResult "Graph app-role $roleId already granted" -Kind Note
            continue
        }
        $null = Grant-GraphAppRole -ServicePrincipalId $sp.Id -GraphServicePrincipalId $graphSp.Id -RoleId $roleId
        Write-UiResult "granted Graph app-role $roleId" -Kind Ok
    }

    Write-EventLogEntry $EID.AppRegistered Information "Entra app '$AppName' configured (appId $($app.AppId))"
    return @{ AppId = [string]$app.AppId; ObjectId = [string]$app.Id }
}

function Grant-GraphAppRole {
    # Assign one Microsoft Graph app-role to the app's service principal, retrying a refusal. A grant posted
    # seconds after New-MgServicePrincipal has been answered with 403 Authorization_RequestDenied for a
    # permanent Global Administrator and then succeeded from the portal minutes later (#128): the new SP had
    # not replicated to whatever answered. Retries 403 / 404 only, on the $GrantRetryDelaysSeconds schedule;
    # anything else fails at once. The final failure carries the portal fallback. Returns the retry count.
    param(
        [Parameter(Mandatory)][string] $ServicePrincipalId,
        [Parameter(Mandatory)][string] $GraphServicePrincipalId,
        [Parameter(Mandatory)][string] $RoleId
    )
    $attempt = 0
    while ($true) {
        try {
            New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ServicePrincipalId -PrincipalId $ServicePrincipalId -ResourceId $GraphServicePrincipalId -AppRoleId $RoleId -ErrorAction Stop | Out-Null
            return $attempt
        }
        catch {
            $retryable = (([string]$_.Exception.Message) + ' ' + ([string]$_.FullyQualifiedErrorId)) -match 'Authorization_RequestDenied|Request_ResourceNotFound'
            if ($retryable -and $attempt -lt $GrantRetryDelaysSeconds.Count) {
                $delay = [int]$GrantRetryDelaysSeconds[$attempt]
                $attempt++
                Write-UiResult "grant of $RoleId refused (attempt $attempt of $($GrantRetryDelaysSeconds.Count + 1)); the new service principal may not have replicated yet - retrying in ${delay}s" -Kind Warn
                Start-Sleep -Seconds $delay
                continue
            }
            throw ((ConvertTo-GraphFailureMessage -Step "Granting Graph app-role $RoleId (admin consent)" -ErrorRecord $_) + ' ' + $PortalConsentFallback)
        }
    }
}

function Set-AppProxyAuthBlock {
    # Write/refresh the shared AppProxyAuth block on the cert-config object (both credential references
    # are public - no secret stored, golden rule). Idempotent.
    #
    # D12/D5: the block carries the field THIS platform reads - AuthCertThumbprint on Windows,
    # AuthCertPath on Linux - and REMOVES the other if it is present, because Get-MachineCredential
    # refuses a block carrying both rather than resolving by precedence. That matters on a re-run
    # against a config copied from a Windows box, which is exactly how a fleet ends up with both.
    param(
        [Parameter(Mandatory)][object] $Config,
        [Parameter(Mandatory)][string] $TenantId,
        [Parameter(Mandatory)][string] $ClientId,
        [AllowEmptyString()][string] $AuthCertThumbprint = '',
        [AllowEmptyString()][string] $AuthCertPath = ''
    )
    # Defence-in-depth: TenantId + ClientId are written here and used to build the AAD token URL at renewal
    # time. Refuse to persist anything that isn't a GUID (e.g. a Graph SDK welcome banner that leaked into
    # the value) - a bad TenantId yields an "Invalid URL" 400 that only surfaces days later on the box.
    # Skipped under -DryRun, where the values are the '(dry-run)' placeholder (nothing is persisted anyway).
    if (-not $DryRun) {
        foreach ($pair in @(@{ N = 'TenantId'; V = $TenantId }, @{ N = 'ClientId'; V = $ClientId })) {
            if (-not (Test-IsGuid $pair.V)) {
                throw "Refusing to write AppProxyAuth: $($pair.N) is not a GUID ('$($pair.V)')."
            }
        }
    }
    $refField = Get-CredentialRefName -ThumbprintField 'AuthCertThumbprint' -PathField 'AuthCertPath'
    $refValue = if ($refField -eq 'AuthCertPath') { $AuthCertPath } else { $AuthCertThumbprint }
    if (-not $DryRun -and [string]::IsNullOrWhiteSpace($refValue)) {
        throw "Refusing to write AppProxyAuth: $refField is empty, and it is the credential reference this platform reads."
    }
    $block = [pscustomobject][ordered]@{
        Enabled            = $true
        TenantId           = $TenantId
        ClientId           = $ClientId
        ApplicationName    = $AppName
    }
    $block | Add-Member -NotePropertyName $refField -NotePropertyValue $refValue
    $Config | Add-Member -NotePropertyName 'AppProxyAuth' -NotePropertyValue $block -Force
    return $Config
}

function Get-CertificateIdentities {
    # The set of FQDNs a Domains[] entry covers (MainDomain + SANs), lowercased, for migration matching.
    param([object] $DomainEntry)
    $ids = @()
    if ($DomainEntry.MainDomain) { $ids += ([string]$DomainEntry.MainDomain).ToLower() }
    if ($DomainEntry.SANs) { foreach ($s in @($DomainEntry.SANs)) { if ($s) { $ids += ([string]$s).ToLower() } } }
    return @($ids | Select-Object -Unique)
}

function Get-OldProxyIdentities {
    # The FQDNs an old AdHoc AppProxies[] entry covers (CN of CertificateSubject + CertificateSANs).
    param([object] $OldProxy)
    $ids = @()
    if ($OldProxy.CertificateSubject -and ([string]$OldProxy.CertificateSubject -match 'CN=([^,]+)')) { $ids += $Matches[1].Trim().ToLower() }
    if ($OldProxy.CertificateSANs) { foreach ($s in @($OldProxy.CertificateSANs)) { if ($s) { $ids += ([string]$s).ToLower() } } }
    return @($ids | Select-Object -Unique)
}

function Add-MigratedAppProxyBindings {
    # Map each AdHoc AppProxies[] entry onto a Domains[] entry by certificate subject/SAN and stamp a
    # per-domain AppProxy block (Add-Member). Returns @{ Mapped = <int>; Unmapped = @(<label>...) }. Pure of
    # I/O (the caller persists), so the migration mapping is unit-testable.
    param([Parameter(Mandatory)][object] $Config, [Parameter(Mandatory)][object] $OldConfig)
    $domains = @(); if ($Config.Domains) { $domains = @($Config.Domains) }
    $mapped = 0; $unmapped = @()
    foreach ($op in @($OldConfig.AppProxies)) {
        $opIds = Get-OldProxyIdentities -OldProxy $op
        $match = $null
        foreach ($d in $domains) {
            $dIds = Get-CertificateIdentities -DomainEntry $d
            if ($dIds | Where-Object { $opIds -contains $_ }) { $match = $d; break }
        }
        if (-not $match) { $unmapped += "$($op.DisplayName) [$($opIds -join ', ')]"; continue }
        $match | Add-Member -NotePropertyName 'AppProxy' -NotePropertyValue ([pscustomobject]@{
            ApplicationObjectId = [string]$op.ApplicationObjectId
            AppId               = [string]$op.AppId
            DisplayName         = [string]$op.DisplayName
        }) -Force
        Write-UiResult "mapped App Proxy '$($op.DisplayName)' $(Get-UiGlyph Arrow) certificate '$($match.MainDomain)'" -Kind Ok
        $mapped++
    }
    return @{ Mapped = $mapped; Unmapped = @($unmapped) }
}

#endregion Helpers ------------------------------------------------------------

#region Main ------------------------------------------------------------------

$exitCode = 0
# Console-UI glyphs: Unicode rules/marks on a UTF-8 console, ASCII elsewhere (mirrors the creator's Main).
try { $script:UiUnicode = ([Console]::OutputEncoding.CodePage -eq 65001) } catch { $script:UiUnicode = $false }
try {
    # -ConfigPath defaults to '' (see param) so the layout is resolved HERE, where Get-PlatformPaths
    # exists: C:\Cert\Renewal on Windows, /etc/certrenewal on Linux. An explicit -ConfigPath still wins.
    if (-not $ConfigPath) { $ConfigPath = (Get-PlatformPaths).Config }
    Write-EventLogEntry $EID.Start Information "Setup-AppProxy v$ScriptVersion starting (Migrate=$Migrate)"
    $dot     = Get-UiGlyph Dot
    $modeStr = if ($Migrate) { 'migrate an existing AdHoc install' } else { 'fresh setup' }
    Write-UiHeader ("cert-renewal {0} Setup-AppProxy v{1}" -f $dot, $ScriptVersion)
    Write-UiField 'Mode'    $modeStr
    Write-UiField 'Config'  $ConfigPath
    Write-UiField 'Dry run' $(if ($DryRun) { 'yes (no changes will be made)' } else { 'no' })
    Write-UiRule

    if (-not (Test-IsElevated)) { throw 'Setup-AppProxy must run elevated (Administrator on Windows, root on Linux) - it writes machine credentials and may unregister a scheduled task.' }

    # D14: there is nothing to migrate FROM on Linux. The AdHoc tool this adopts was a Windows product -
    # a C:\Cert\AppProxy folder and a Windows scheduled task - so refuse here, in one line that names the
    # reason, rather than failing somewhere deep in the flow at Get-ScheduledTask.
    if ($Migrate -and -not $IsWindowsHost) {
        throw '-Migrate adopts an existing AdHoc App Proxy install, which only ever existed on Windows (C:\Cert\AppProxy plus a scheduled task). There is no Linux install to adopt - run without -Migrate for a fresh setup.'
    }

    $config = Get-CertConfig

    Write-UiHeader 'Microsoft Graph'
    Install-GraphModules
    # Connect-SetupGraph does the sign-in + a GUID sanity check, but we deliberately DON'T trust its return
    # value: some Graph SDK versions emit the welcome/connection banner to the success stream even with
    # -NoWelcome + redirection, which contaminates any function return. Discard the return and read the
    # tenant id straight off the SDK context object (always a clean GUID) instead.
    $null = Connect-SetupGraph
    $tenantId = if ($DryRun) { $null } else { [string](Get-MgContext -ErrorAction Stop).TenantId }

    Write-UiHeader 'Authentication certificate'
    $authCert = Get-OrCreateAuthCertificate -Config $config

    Write-UiHeader 'Entra application'
    $entraApp = Get-OrCreateEntraApp -AuthCertificate $authCert

    # The two credential references, mutually exclusive by platform (D5/D12). Set-AppProxyAuthBlock
    # persists the one Get-CredentialRefName names and drops the other; under -DryRun nothing is minted,
    # so the thumbprint is a placeholder while the PATH is still real - it is where the credential WOULD
    # have been written, and printing it is the only way a dry run can show the operator that.
    $authThumb = if ($authCert) { $authCert.Thumbprint } else { '(dry-run)' }
    # The file the mint actually used, not a re-derived one - a mint-beside has just changed which file
    # that is. Only -DryRun (no certificate) falls back to resolving it, and nothing is persisted then.
    $authPath  = if ($IsWindowsHost) { '' }
                 elseif ($authCert -and $authCert.CredentialPath) { [string]$authCert.CredentialPath }
                 else { Get-AuthCertPemPath -ConfiguredPath ([string]$config.AppProxyAuth.AuthCertPath) }
    $clientId  = $entraApp.AppId
    $tenant    = if ($tenantId) { $tenantId } else { '(dry-run)' }
    $mapped = 0; $unmapped = @()

    if ($Migrate) {
        Write-UiHeader 'Migrate existing AdHoc App Proxy install'
        if (-not (Test-Path $OldAppProxyConfigPath)) { throw "No AdHoc config found at $OldAppProxyConfigPath - nothing to migrate (run without -Migrate for a fresh setup)." }
        $old = Get-Content $OldAppProxyConfigPath -Raw | ConvertFrom-Json

        # Reuse the AdHoc app + auth cert when present (no re-register) by preferring the old config's IDs.
        if ($old.ClientId)                 { $clientId = [string]$old.ClientId }
        if ($old.TenantId)                 { $tenant   = [string]$old.TenantId }
        if ($old.AuthCertificateThumbprint -and ($authThumb -eq '(dry-run)')) { $authThumb = [string]$old.AuthCertificateThumbprint }

        $config = Set-AppProxyAuthBlock -Config $config -TenantId $tenant -ClientId $clientId -AuthCertThumbprint $authThumb -AuthCertPath $authPath

        # Map each old AppProxies[] entry onto a Domains[] entry by certificate subject/SAN.
        $map = Add-MigratedAppProxyBindings -Config $config -OldConfig $old
        $mapped = $map.Mapped; $unmapped = @($map.Unmapped)
        if ($unmapped.Count -gt 0) {
            Write-UiResult "could not map $($unmapped.Count) App Proxy entry(ies) - no managed cert matches their subject/SAN:" -Kind Warn
            foreach ($u in $unmapped) { Write-UiResult $u -Kind Warn }
            Write-UiResult 'add the matching cert via Create-New-Cert.ps1, then re-run -Migrate (or wire it via the creator''s Update flow).' -Kind Note
        }

        Save-Config -Config $config -Reason 'AppProxy migration'

        # Unregister the AdHoc scheduled task + archive its scripts/config (the renewal handles it inline now).
        # Gated on the host rather than leaning on -Migrate being refused on Linux further up: these two
        # cmdlets do not exist there at all, and a gate you can only reach by reasoning about an earlier
        # refusal is not one a structural test can see - which made that test vacuous for all of Main.
        if ($IsWindowsHost) {
            $task = Get-ScheduledTask -TaskName $OldAppProxyTaskName -ErrorAction SilentlyContinue
            if ($task) {
                if ($DryRun) { Write-Log "[DryRun] WOULD unregister the AdHoc scheduled task '$OldAppProxyTaskName'." -Level INFO }
                else { Unregister-ScheduledTask -TaskName $OldAppProxyTaskName -Confirm:$false; Write-UiResult "unregistered the AdHoc scheduled task '$OldAppProxyTaskName'" -Kind Ok }
            }
            else { Write-UiResult "no AdHoc scheduled task '$OldAppProxyTaskName' (already removed?)" -Kind Note }
        }

        $oldDir = Split-Path -Parent $OldAppProxyConfigPath
        if ($oldDir -and (Test-Path $oldDir)) {
            $archive = "$oldDir.migrated-{0}" -f (Get-Date -Format 'yyyyMMdd-HHmmss')
            if ($DryRun) { Write-Log "[DryRun] WOULD archive the old AdHoc folder $oldDir -> $archive." -Level INFO }
            else {
                try { Rename-Item -Path $oldDir -NewName (Split-Path -Leaf $archive) -ErrorAction Stop; Write-UiResult "archived the old AdHoc folder $(Get-UiGlyph Arrow) $archive" -Kind Ok }
                catch { Write-UiResult "could not archive $oldDir (in use?): $($_.Exception.Message). Remove it manually once you've confirmed the migration." -Kind Warn }
            }
        }

        Write-EventLogEntry $EID.Migrated Information "AdHoc App Proxy install migrated ($mapped mapped, $($unmapped.Count) unmapped)"
    }
    else {
        # Fresh setup: just write the shared AppProxyAuth block. Per-domain wiring is done in the creator.
        $config = Set-AppProxyAuthBlock -Config $config -TenantId $tenant -ClientId $clientId -AuthCertThumbprint $authThumb -AuthCertPath $authPath
        Save-Config -Config $config -Reason 'AppProxy fresh setup'
    }

    if (-not $DryRun) {
        try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
    }

    Write-UiHeader 'Summary'
    Write-UiField 'Tenant'      $tenant
    Write-UiField 'Application' ("{0} ({1})" -f $AppName, $clientId)
    Write-UiField 'Auth cert'   $(if ($IsWindowsHost) { $authThumb } else { "$authThumb ($authPath)" })
    if ($Migrate) { Write-UiField 'Mapped' ("{0} App Proxy app(s){1}" -f $mapped, $(if ($unmapped.Count) { ", $($unmapped.Count) unmapped" } else { '' })) }
    Write-UiRule
    if ($Migrate) {
        Write-UiResult 'migration complete - the daily renewal now keeps App Proxy in sync.' -Kind Ok
    }
    else {
        Write-UiResult 'fresh setup complete.' -Kind Ok
        Write-UiResult 'next: wire each certificate to an App Proxy app via Create-New-Cert.ps1 (Add or Update).' -Kind Note
    }
}
catch {
    Write-Log "FATAL: $($_.Exception.Message)" -Level ERROR
    Write-EventLogEntry $EID.Failed Error "Setup-AppProxy failed: $($_.Exception.Message)"
    $exitCode = 1
}

exit $exitCode

#endregion Main ---------------------------------------------------------------

# SIG # Begin signature block
# MIIeDwYJKoZIhvcNAQcCoIIeADCCHfwCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCCG5Psy2bmijQq
# sWz768nDCpYhHKEpjU3S6TwbfnxFk6CCF6gwggRqMIIC0qADAgECAhA9a+7a4tnR
# tULR4ioNgMJCMA0GCSqGSIb3DQEBCwUAME0xCzAJBgNVBAYTAk5PMREwDwYDVQQK
# DAhJdGVhbSBBUzErMCkGA1UEAwwiSXRlYW0gQVMgQ2VydC1SZW5ld2FsIENvZGUg
# U2lnbmluZzAeFw0yNjA2MDQxMTQyMTJaFw0zNjA2MDQxMTUyMTJaME0xCzAJBgNV
# BAYTAk5PMREwDwYDVQQKDAhJdGVhbSBBUzErMCkGA1UEAwwiSXRlYW0gQVMgQ2Vy
# dC1SZW5ld2FsIENvZGUgU2lnbmluZzCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCC
# AYoCggGBANUUjgkrBhDB8TKKeXmFo+7dwNPadI/JK+BNGlBiVwKWYJey7wWkX8fg
# 5bP9JJeH//jpBPAsMCkTOa1jlCcpNz4BESjnDqosZ6oI3taoy4Srm3mVpPxh2yDf
# lAt8V5KEIZM+QZVWHEUNZU7m2Akacmo6Sb5/ORQ3lgoLVoiEmriVcebZLHMmCJdo
# AqiA63aQjyneFj6eUhfGQE9h6mAUODZWNubEPyUQF1A2DiN4toSHHaWacTL1qoda
# /mNvO34iUQckpwpKS7avSSUQijnsv3w4ITB/Hf4JgL9O5oSBWVcTCWLX0RyO0Qdp
# RE69QZGP2XZcohVc6VZllawMuJ1O3BhbAW09iycjhZGx1sPEgd5ERRQGndY/8XHA
# iW/7/yUSnRS3MKrnW8Ls2MV14EL0T08qK+300ZUWShuqM9vv8fDNoZ9NG8DGRKxm
# pqeG3pBBXsywTQ8iyl41hKodteZ3J+4uztlRyFw5sYahjIniKH5+MtS5xGWb3M2B
# gGY0gf7OOQIDAQABo0YwRDAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYB
# BQUHAwMwHQYDVR0OBBYEFF3lGiJjk0pn+ksLKLjPPTfF6PQiMA0GCSqGSIb3DQEB
# CwUAA4IBgQCyVitqOQk52FEw6oBCNfeWwKPE/ifm5TMmZaB0EOU9vabuCLjS7rF+
# o+wGD9d7EPxiG6dBmEcZ8TPudJaT2Hcvt/59Qlh3bD0gEGolpCaSjlxCEwL5QSBW
# eY48vvZkwIqMR4XOL3ZnQDYEU3LnbmihwCH18XuhHI7QB+KuLQF5F4trdTx2tfEx
# kL9ZqO7VyPVk6Sq54rol0fBeEmgLdX1oEJzf8koS2X6Kjl6kBIysDjCDDD2bRELA
# INF9rpn/D0IHeii01g9LHO+YZ6K47Mi6hUOOI0XqQgBNhNmLRdGHSJpEp8NDOHFr
# RX65ROlOCNdcazwviPnoaXLLErmwF3AeFin9E7xv1+RJTO+j92k++sB8/HspJjq3
# pBRcFQ+oQ2BK4CI7/AoEK/RKPhU2qrUDWLtOgXtoozkpWdfltoURtajsrQ2umiAA
# 8kIRWZHvrKb01RwZSMrOACRRVcBqGkRdj5zCTIIyk5EQ3l5mfL1O5Eo+9MFDP19m
# bcKkfiZWOnYwggWNMIIEdaADAgECAhAOmxiO+dAt5+/bUOIIQBhaMA0GCSqGSIb3
# DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAX
# BgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0IEFzc3Vy
# ZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBaFw0zMTExMDkyMzU5NTlaMGIx
# CzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3
# dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBH
# NDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAL/mkHNo3rvkXUo8MCIw
# aTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3EMB/zG6Q4FutWxpdtHauyefLK
# EdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKyunWZanMylNEQRBAu34LzB4Tm
# dDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsFxl7sWxq868nPzaw0QF+xembu
# d8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU15zHL2pNe3I6PgNq2kZhAkHnD
# eMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJBMtfbBHMqbpEBfCFM1LyuGwN1
# XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObURWBf3JFxGj2T3wWmIdph2PVld
# QnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6nj3cAORFJYm2mkQZK37AlLTS
# YW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxBYKqxYxhElRp2Yn72gLD76GSm
# M9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5SUUd0viastkF13nqsX40/ybzT
# QRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+xq4aLT8LWRV+dIPyhHsXAj6Kx
# fgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIBNjAPBgNVHRMBAf8EBTADAQH/
# MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwPTzAfBgNVHSMEGDAWgBRF66Kv
# 9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMCAYYweQYIKwYBBQUHAQEEbTBr
# MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQwYIKwYBBQUH
# MAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJ
# RFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNl
# cnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDARBgNVHSAECjAIMAYG
# BFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0NcVec4X6CjdBs9thbX979XB72a
# rKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnovLbc47/T/gLn4offyct4kvFID
# yE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65ZyoUi0mcudT6cGAxN3J0TU53/o
# Wajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFWjuyk1T3osdz9HNj0d1pcVIxv
# 76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPFmCLBsln1VWvPJ6tsds5vIy30
# fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9ztwGpn1eqXijiuZQwgga0MIIE
# nKADAgECAhANx6xXBf8hmS5AQyIMOkmGMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNV
# BAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdp
# Y2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0y
# NTA1MDcwMDAwMDBaFw0zODAxMTQyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYD
# VQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBH
# NCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEwggIiMA0GCSqG
# SIb3DQEBAQUAA4ICDwAwggIKAoICAQC0eDHTCphBcr48RsAcrHXbo0ZodLRRF51N
# rY0NlLWZloMsVO1DahGPNRcybEKq+RuwOnPhof6pvF4uGjwjqNjfEvUi6wuim5ba
# p+0lgloM2zX4kftn5B1IpYzTqpyFQ/4Bt0mAxAHeHYNnQxqXmRinvuNgxVBdJkf7
# 7S2uPoCj7GH8BLuxBG5AvftBdsOECS1UkxBvMgEdgkFiDNYiOTx4OtiFcMSkqTtF
# 2hfQz3zQSku2Ws3IfDReb6e3mmdglTcaarps0wjUjsZvkgFkriK9tUKJm/s80Fio
# cSk1VYLZlDwFt+cVFBURJg6zMUjZa/zbCclF83bRVFLeGkuAhHiGPMvSGmhgaTzV
# yhYn4p0+8y9oHRaQT/aofEnS5xLrfxnGpTXiUOeSLsJygoLPp66bkDX1ZlAeSpQl
# 92QOMeRxykvq6gbylsXQskBBBnGy3tW/AMOMCZIVNSaz7BX8VtYGqLt9MmeOreGP
# RdtBx3yGOP+rx3rKWDEJlIqLXvJWnY0v5ydPpOjL6s36czwzsucuoKs7Yk/ehb//
# Wx+5kMqIMRvUBDx6z1ev+7psNOdgJMoiwOrUG2ZdSoQbU2rMkpLiQ6bGRinZbI4O
# Lu9BMIFm1UUl9VnePs6BaaeEWvjJSjNm2qA+sdFUeEY0qVjPKOWug/G6X5uAiynM
# 7Bu2ayBjUwIDAQABo4IBXTCCAVkwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4E
# FgQU729TSunkBnx6yuKQVvYv1Ensy04wHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5n
# P+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMIMHcG
# CCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQu
# Y29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGln
# aUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8v
# Y3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAgBgNV
# HSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggIB
# ABfO+xaAHP4HPRF2cTC9vgvItTSmf83Qh8WIGjB/T8ObXAZz8OjuhUxjaaFdleMM
# 0lBryPTQM2qEJPe36zwbSI/mS83afsl3YTj+IQhQE7jU/kXjjytJgnn0hvrV6hqW
# Gd3rLAUt6vJy9lMDPjTLxLgXf9r5nWMQwr8Myb9rEVKChHyfpzee5kH0F8HABBgr
# 0UdqirZ7bowe9Vj2AIMD8liyrukZ2iA/wdG2th9y1IsA0QF8dTXqvcnTmpfeQh35
# k5zOCPmSNq1UH410ANVko43+Cdmu4y81hjajV/gxdEkMx1NKU4uHQcKfZxAvBAKq
# MVuqte69M9J6A47OvgRaPs+2ykgcGV00TYr2Lr3ty9qIijanrUR3anzEwlvzZiiy
# fTPjLbnFRsjsYg39OlV8cipDoq7+qNNjqFzeGxcytL5TTLL4ZaoBdqbhOhZ3ZRDU
# phPvSRmMThi0vw9vODRzW6AxnJll38F0cuJG7uEBYTptMSbhdhGQDpOXgpIUsWTj
# d6xpR6oaQf/DJbg3s6KCLPAlZ66RzIg9sC+NJpud/v4+7RWsWCiKi9EOLLHfMR2Z
# yJ/+xhCx9yHbxtl5TPau1j/1MIDpMPx0LckTetiSuEtQvLsNz3Qbp7wGWqbIiOWC
# nb5WqxL3/BAPvIXKUjPSxyZsq8WhbaM2tszWkPZPubdcMIIG7TCCBNWgAwIBAgIQ
# CE/cM09+RU7bww+P+ZIYNTANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQGEwJVUzEX
# MBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0
# ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMB4XDTI2
# MDgwNTAwMDAwMFoXDTM3MTEwNDIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAVBgNV
# BAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBTSEEyNTYgUlNB
# NDA5NiBUaW1lc3RhbXAgUmVzcG9uZGVyIDIwMjYgMTCCAiIwDQYJKoZIhvcNAQEB
# BQADggIPADCCAgoCggIBALZ7pvLJ/s1K+NSbTGWz/TjGMPh8CQ6RucZCLv5anHzW
# JjF/NWJrFIhy24fcpKXlgRiky4WAawDfU3YP0BMxt9l3Dm5oCG5Z69AqEN1kgHg2
# epx+l+lZBcmJCcN0ASURML5uFIS80sZsDwO3BSkUxDjLJhBI+qiZP3aixAC/qEGL
# jsBNlLol9VZ7pfGEXiMlneJIC5/YKuizVzNFKZZEeoy/0B8Zm+nzKBgSWG52lCO1
# w+nCg6XpCtklTJXeIg283hw7TmmsZXR+SMbjbrEOvZ3fP2VxIgeR28Y90ZStd3F9
# VuA5RVynb/whITPAo9b75Zr4Ta6Mj3URm26QZYMn/FnbuTegcoRcFEZ9FOqM5T6M
# Tdtr/n74lIT/ug0eeOzmZ6QTFg33otX+bFRsIolvykE1jive4PuESaT8zzVeFWDA
# MDtozNgLctkGD1ZjkEyZtJrLl5ya0m5doH/ScpaZCZVl6pNUOCybMc/kxC6EAmSJ
# Y24L0yYKD1Nkddsnb/ItVKi/2nXpQNMu1PT5prW83vV8d67WowuUs0HdY4H8AMLG
# vdL/WHEj3ZnqMqAQQP9u3Ai9t+5eQ02GDwy0ODjdzi0xlp70W+ow63/0++YDEX1M
# 0iwgUHwbrJvfpklkZQvw3+kv3vUPItdwroczk9icflf55W1zOEKAcJVAIXpcMCU9
# AgMBAAGjggGVMIIBkTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQUyWOKMC7USvtu
# lPPm40B+9ezN4jAfBgNVHSMEGDAWgBTvb1NK6eQGfHrK4pBW9i/USezLTjAOBgNV
# HQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwgZUGCCsGAQUFBwEB
# BIGIMIGFMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXQYI
# KwYBBQUHMAKGUWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRy
# dXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNydDBfBgNV
# HR8EWDBWMFSgUqBQhk5odHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRU
# cnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5jcmwwIAYD
# VR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4IC
# AQCNxTphHp1SCt+ZrAmAfn0oQLFr0mLywSLaDXQIENoyKqxrFbJblzCVP/pkXmwX
# OdrOpWygLzlT12os5ipDCy35RBCg2UMeApEtrfGhz45F4Wt4WGdNdIbRWt3YTYJm
# pR+b7lr4d7Uwn+H600u4D7RnOGf8Wj4UNgAdZkfHhHv1mx9EVh71SJelcEN/oORS
# jXzdjfw1iZH9d8Nh/thn6hH23d+VsPAr6GAYyzSA02nXD1nYLI7Ijmiv+xLCiYC4
# 1DSFYL3GhTiy0PxpawPtGRyaBVGzq+UiTfM8pD7KVyF5aQyWP4KhVGUUTnmm/RlY
# JoW3TiXA/+t0YcT2oRVBm3JETjajHug2AL+v5jhtKVnd3D0rbHXEu27o+Q8p4sEW
# PMqKDB+qbceb6T/6WcwTwXmQ9lOCLLYcsQeSWmvKqzpAec9etE14jOQAzLKWdE3w
# /TCaKtLRaRT7LCkRYVnhA2D73FLje1O5b3HR5eHs0NzU/+xX7NbEdcofy0W3Wdwd
# 1XOqtlpg/JgwtKfZM5dqO94lbUveOiJBI+xZEbGRsMNbXmMREUTgu+Oca7Y73MPW
# cslIx2VhkSKSXjDbD6rgg39H5Mh7QfieAIjWagkJNt68Yfim6cjEzVSiLSeZfdkr
# 5dtFPTW6jATlWJdYeeDRGCyatf8R1hSjzSvdN8yWQPT9gzGCBb0wggW5AgEBMGEw
# TTELMAkGA1UEBhMCTk8xETAPBgNVBAoMCEl0ZWFtIEFTMSswKQYDVQQDDCJJdGVh
# bSBBUyBDZXJ0LVJlbmV3YWwgQ29kZSBTaWduaW5nAhA9a+7a4tnRtULR4ioNgMJC
# MA0GCWCGSAFlAwQCAQUAoIGEMBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJ
# KoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQB
# gjcCARUwLwYJKoZIhvcNAQkEMSIEIMZMwCq3WfTtonNn81UC5wzWEbwkzSsCDgkY
# UDq9S2UCMA0GCSqGSIb3DQEBAQUABIIBgHUEISSRWARkuGFp5BR+hJF/QnFPV9jR
# OOLqaXHlr5CHzEMxSLSyG2WOAbVNgiFfBw9aDM903z3trH1Fjqy3nE2dixKK+nmC
# YGS+9E5eNr3FSllLD5+9eq/K0m1Xr0lzbe85pi0ILMSXlE5r0PsML6Vv9B17mt+x
# fuVFPNQMJ+Hw6HOVkXQM2yhRH5epCsQU42z+SvjM+VlW3JzvG4W27ZdPwm1gR9Zu
# s189L41mCh94vIW1RszrC22ky1jN5HrbLQR9ee1LPI04COLCrcJN4rEo8W37kz1m
# vKhacb7mMJonXhn1fPHJVSXxUnFmbhC4PR/NHt32DEmvcJaSqQ5FC23PWzMkJjAD
# 0U+o3zdfI4qgqz97YgarvZiiB9cpQAUrNpmnwzv4mKSefLzt/jJlzkzEbU+cd0gS
# 1vevxV2xsDzkCTQ9gSrAreeaM5/JD64zxJja6gpq+QHgJGOartFgNe+4iRimY3iG
# aN/ENVHwXCXhfDMF4ufrbdlCDYVcIBs666GCAyYwggMiBgkqhkiG9w0BCQYxggMT
# MIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5j
# LjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNB
# NDA5NiBTSEEyNTYgMjAyNSBDQTECEAhP3DNPfkVO28MPj/mSGDUwDQYJYIZIAWUD
# BAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEP
# Fw0yNjA5MjkwODQ3MTVaMC8GCSqGSIb3DQEJBDEiBCC7WWK+wRGijtNEvPKz/yCT
# oZxkyZP/gvaTQpN8krhBxzANBgkqhkiG9w0BAQEFAASCAgB08rC7lIWASRMXXl+c
# BDr/BFk+JtIMbZ+uN9dO05aCVlZYRTLlsjU7NTD++FCLug12VvtKtOpDRmfWWvyM
# xacu+eZXknnPCO16je2sqXAhxTqQiSejRr7JDQbjKIpjPYqARNFl/g3qbWpqeIGG
# Wma3g1T5sliKPaHTiVS/U8PRBL8u4WMRY74JWUg+JajnETTNw8DDQNu3xqEv5jSf
# OB6iw0cTgkD7EqZO7ZIlvB2JxTt/+UyfeVHzhr0zd9XvRglpf2CMhWvlEgwgtFVM
# +88qcvGd+lrCLGJegNt9zWvcNqk2c9gJD1py66wBRYNnxwLkqWgqsUhAdFjU2puS
# BnuWhvGDSeOwaufIjH03mF4YkPkL1pMaL0HfFB4lH6Z1tso1yfnJ0nCIyWYg5L9t
# 9I/YlHI+vX1BwVVzcOKba86BYAk9YYJcW2s60POuEReWEeBygmOFy99x2sokG6Yz
# A2UsQkcMjCKpeaU75n0T6y3TgfJcg+ZVUl34fvkkVKCIm8MlR/rCzExyBtfsE6vw
# q28reXdEvf0M/2NNcmVPP1tAmNCpAZmZEYCzz2OfmDcIBmlMrc2kT4ZjvBXBJwMo
# sL+uRbwvMWiOHX1CUwwPVgekYLVYpYCDUzqv3P2dTwboLuc/ibB9kLg7+s/AxGrw
# h0gCvI5P+eKv2r0eIIBYoyw7yg==
# SIG # End signature block
